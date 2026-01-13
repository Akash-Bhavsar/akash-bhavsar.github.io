---
layout: page
title: API Security Scanner
description: Custom nuclei templates for API security testing
img: assets/img/api-security.jpg
importance: 1
category: security-tools
---

A collection of custom Nuclei templates specifically designed for API security testing.

## Features

- Authentication bypass detection
- BOLA/IDOR vulnerability scanning
- JWT misconfiguration checks
- Rate limiting validation
- Mass assignment detection

## Usage

```bash
nuclei -t api-security-templates/ -u https://api.target.com
```

## Templates Included

| Template | Description |
|----------|-------------|
| jwt-none-alg.yaml | JWT 'none' algorithm check |
| bola-check.yaml | Broken Object Level Authorization |
| auth-bypass.yaml | Authentication bypass patterns |
| rate-limit.yaml | Rate limiting validation |

---

*This is a placeholder project. Replace with your actual security tools!*
