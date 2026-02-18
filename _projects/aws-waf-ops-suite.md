---
layout: page
title: AWS WAF Security Operations Suite
description: A production-grade AWS WAF deployment protecting web applications against OWASP Top 10 threats. Deploys 10 custom WAF rules (SQLi, XSS, rate limiting, bot detection, geo-blocking, CSRF) in front of CloudFront, with CloudWatch dashboards, CloudTrail audit logging, and an automated threat detection engine that auto-blocks malicious IPs. Includes 30+ attack vector tests and full IaC via Python and boto3.
importance: 4
category: security
github: https://github.com/Akash-Bhavsar/WAF-Ops-Suite
github_stars: Akash-Bhavsar/WAF-Ops-Suite
---

A production-grade AWS WAF deployment that protects web applications against the OWASP Top 10 threats. Deploys 10 custom WAF rules in front of a CloudFront CDN, with real-time monitoring and an automated threat detection engine.

**Key Features:**
- 10 custom WAF rules: SQL injection, XSS, rate limiting, bot detection, geo-blocking, CSRF protection
- CloudFront CDN integration for edge-level protection
- CloudWatch dashboards and alarms for real-time monitoring
- CloudTrail audit logging for compliance and forensics
- Automated threat detection engine that identifies attack campaigns and auto-blocks malicious IPs
- Comprehensive testing suite with 30+ attack vectors
- Full Infrastructure-as-Code deployment via Python and boto3
