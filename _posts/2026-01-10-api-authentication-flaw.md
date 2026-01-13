---
layout: post
title: Breaking Down an API Authentication Flaw
date: 2026-01-10 12:00:00
description: A walkthrough of a real-world JWT 'none' algorithm vulnerability
tags: appsec api-security owasp
categories: writeups
giscus_comments: true
---

In this post, I walk through a real-world API authentication issue, why it happens, and how teams can prevent it.

## The Scenario

During a recent penetration test engagement, I discovered a critical authentication bypass in a REST API. The application relied on JWT tokens for authentication, but the implementation had a subtle flaw that allowed attackers to forge valid tokens.

## The Vulnerability

The API accepted JWTs signed with the `none` algorithm. This is a classic mistake that occurs when:

1. The JWT library supports the `none` algorithm by default
2. Developers don't explicitly enforce algorithm validation
3. Token verification only checks the signature matches—not that a signature exists

```python
# Malicious token with 'none' algorithm
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"user_id": "admin", "role": "administrator"}

# Encode without signature
token = (
    base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode() +
    "." +
    base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode() +
    "."
)
print(token)
```

## Impact

An attacker could:
- Forge tokens for any user account
- Escalate privileges to administrator
- Access sensitive data across the entire platform

## Remediation

Here's how to prevent this vulnerability:

1. **Explicitly specify allowed algorithms** during verification
2. **Reject tokens with `alg: none`** at the validation layer
3. **Use well-maintained JWT libraries** with secure defaults
4. **Implement token binding** to tie tokens to specific sessions

```python
# Secure JWT verification
import jwt

def verify_token(token):
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],  # Explicitly allow only HS256
        options={"require": ["exp", "iat"]}
    )
```

## Defensive Takeaways

- Never trust client-supplied algorithm headers
- Defense in depth: validate tokens at multiple layers
- Regular security testing catches these issues before attackers do

---

*Have questions about API security? Feel free to reach out on [LinkedIn](https://linkedin.com/in/bhavsar667).*
