<p align="center">
  <img src="https://img.shields.io/npm/v/guardrail-scanner?color=green&label=npx%20guardrail" alt="npm">
  <img src="https://img.shields.io/github/license/xiaohou2503687-design/guardrail" alt="license">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs">
</p>

# 馃洝锔?GuardRail

> **One-command security scanner for indie projects. Find secrets, OWASP vulns, and bad deps before they find you.**

```bash
npx guardrail scan
```

---

## 馃槺 The Problem

Every week, indie developers accidentally push API keys to GitHub. 90% of solo projects have zero security scanning. One leaked key = one drained AWS bill.

GuardRail fixes this. One command. No config. No SaaS BS.

---

## 鈿?Quick Start

```bash
# Scan your project
npx guardrail scan

# Scan a specific directory
npx guardrail scan --path ./my-app

# Export a Markdown report
npx guardrail report

# JSON output for CI/CD
npx guardrail scan --json
```

---

## 馃攳 What It Scans

| Scanner | What It Finds | Rules |
|---------|--------------|-------|
| 馃攽 **Secrets** | AWS keys, GitHub tokens, Stripe keys, OpenAI/Claude/DeepSeek API keys, Slack webhooks, DB URLs, private keys | 15 regex rules |
| 馃摝 **Dependencies** | npm audit + 30+ known CVEs (lodash, axios, next, vite, express...) | Built-in vuln DB |
| 馃悰 **OWASP** | XSS, SQL injection, eval(), command injection, insecure CORS, debug mode | 15 patterns |
| 鈿欙笍 **Config** | .gitignore gaps, Docker :latest, .npmrc tokens, YAML secrets | 6 checks |

---

## 馃搳 Example Output

```
鈺斺晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晽
鈺? 馃洝锔? GuardRail Security Scan Report      鈺?鈺氣晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨暆

  Security Score:  72/100   Grade:  C

   2 CRITICAL   3 HIGH  5 MEDIUM  1 LOW

馃攽 Secrets & Credentials (2)
  馃敶 CRITICAL  .env
     AWS Access Key ID exposed
  馃敶 CRITICAL  src/config.js:15
     Stripe Live Secret Key exposed

馃摝 Dependencies (3)
  馃敶 CRITICAL  next@14.0.0
     Server-Side Request Forgery (CVE-2024-46995)
     Fix: Update to next@^14.2.15
```

---

## 馃挵 Pricing

| Plan | Price | Features |
|------|-------|----------|
| **Free** | $0 forever | CLI scanner, all 40+ rules, terminal report |
| **Pro** | **$12/mo** | CI/CD integration, history tracking, AI fix suggestions |
| **Lifetime** | **$99 once** | Everything in Pro, forever |

**[馃憠 Buy Pro / Lifetime](https://xiaohou2503687-design.github.io/guardrail/pricing)**

---

## 馃専 Why GuardRail?

- **Zero config** 鈥?works on any project instantly
- **40+ detection rules** 鈥?secrets, OWASP, deps, config
- **Offline-first** 鈥?no data sent anywhere
- **Open source** 鈥?MIT license, audit the code yourself
- **CI/CD ready** 鈥?`--json` flag for GitHub Actions

---

## 馃 Sponsors & Support

猸?**Star this repo** if you find it useful!

<a href="https://github.com/sponsors/xiaohou2503687-design"><img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-%23db61a2?logo=github"></a>
<a href="https://ko-fi.com/shipfast"><img src="https://img.shields.io/badge/Ko--fi-Buy%20me%20a%20coffee-ff5e5b?logo=ko-fi"></a>

---

<p align="center">
  <sub>Built with 鉂わ笍 by <a href="https://github.com/xiaohou2503687-design">chunfeng3681</a> | MIT License</sub>
</p>
