---
title: "Source Code Analysis: Finding an Auth Bypass in an Open Source App"
date: 2026-03-12 00:00:00 +0300
categories: [write-up, source-code-analysis]
tags: [auth-bypass, php, open-source]
---

## Overview

This write-up documents a source code analysis session where we identified an authentication bypass vulnerability in an open source web application. The goal is to walk through the thought process — what to look for, where to look, and how a small oversight leads to a critical bug.

> **Disclaimer:** This research was conducted on a local instance for educational purposes.

---

## Target

A self-hosted PHP web application (anonymized). Version analyzed: `v2.3.1`.

---

## Starting Point: Entry Points

When approaching a new codebase, the first step is mapping the entry points — files that handle user input directly.

```
find . -name "*.php" | xargs grep -l "\$_GET\|\$_POST\|\$_REQUEST"
```

This gives us a list of files worth auditing first. One file immediately stands out: `auth/login.php`.

---

## The Vulnerable Code

Inside `login.php`, the session check looks like this:

```php
function checkSession($userId) {
    if (isset($_SESSION['user_id'])) {
        return true;
    }

    // fallback: check token param
    if ($_GET['token'] == $userId) {
        $_SESSION['user_id'] = $userId;
        return true;
    }

    return false;
}
```

At first glance this looks fine. But notice the comparison:

```php
$_GET['token'] == $userId
```

This uses loose comparison (`==`) instead of strict comparison (`===`).

---

## The Bug: Type Juggling

In PHP, loose comparison has a well-known quirk. When comparing a string to `0` (integer zero):

```php
var_dump("any_string" == 0); // bool(true)
```

Any arbitrary string equals `0` under loose comparison. So if `$userId` is `0` (e.g., for the admin account), passing `?token=hacked` in the URL satisfies the condition and grants access.

---

## Proof of Concept

```
GET /dashboard?token=anything HTTP/1.1
Host: target.local
```

Result: Authenticated session created for user ID `0` (admin).

---

## Root Cause

The developer likely intended the token as a temporary fallback mechanism, but:

1. Used loose `==` instead of strict `===`
2. Did not validate or expire the token
3. Admin account had ID `0`, making it trivially exploitable

---

## Fix

```php
// Strict comparison + constant-time comparison for tokens
if (hash_equals((string)$userId, (string)$_GET['token'])) {
```

Or better — remove the fallback entirely and use a proper session management library.

---

## Takeaway

Type juggling bugs are classic PHP pitfalls. When doing source code analysis, any comparison involving user-controlled input is worth auditing — especially in authentication logic. The `==` vs `===` distinction is small but the impact can be total auth bypass.
