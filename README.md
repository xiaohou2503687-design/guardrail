<p align="center">
  <img src="https://img.shields.io/npm/v/guardrail-scanner?color=green&label=npx%20guardrail" alt="npm">
  <img src="https://img.shields.io/github/license/xiaohou2503687-design/guardrail" alt="license">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs">
</p>

# 棣冩礉閿?GuardRail

> **One-command security scanner for indie projects. Find secrets, OWASP vulns, and bad deps before they find you.**

```bash
npx guardrail scan
```

---

## 棣冩Ш The Problem

Every week, indie developers accidentally push API keys to GitHub. 90% of solo projects have zero security scanning. One leaked key = one drained AWS bill.

GuardRail fixes this. One command. No config. No SaaS BS.

---

## 閳?Quick Start

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

## 棣冩敵 What It Scans

| Scanner | What It Finds | Rules |
|---------|--------------|-------|
| 棣冩斀 **Secrets** | AWS keys, GitHub tokens, Stripe keys, OpenAI/Claude/DeepSeek API keys, Slack webhooks, DB URLs, private keys | 15 regex rules |
| 棣冩憹 **Dependencies** | npm audit + 30+ known CVEs (lodash, axios, next, vite, express...) | Built-in vuln DB |
| 棣冩偘 **OWASP** | XSS, SQL injection, eval(), command injection, insecure CORS, debug mode | 15 patterns |
| 閳挎瑱绗?**Config** | .gitignore gaps, Docker :latest, .npmrc tokens, YAML secrets | 6 checks |

---

## 棣冩惓 Example Output

```
閳烘柡鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫧
閳? 棣冩礉閿? GuardRail Security Scan Report      閳?閳烘埃鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ櫜閳烘劏鏅查埡鎰ㄦ殕

  Security Score:  72/100   Grade:  C

   2 CRITICAL   3 HIGH  5 MEDIUM  1 LOW

棣冩斀 Secrets & Credentials (2)
  棣冩暥 CRITICAL  .env
     AWS Access Key ID exposed
  棣冩暥 CRITICAL  src/config.js:15
     Stripe Live Secret Key exposed

棣冩憹 Dependencies (3)
  棣冩暥 CRITICAL  next@14.0.0
     Server-Side Request Forgery (CVE-2024-46995)
     Fix: Update to next@^14.2.15
```

---

## 棣冩尩 Pricing

| Plan | Price | Features |
|------|-------|----------|
| **Free** | $0 forever | CLI scanner, all 40+ rules, terminal report |
| **Pro** | **$12/mo** | CI/CD integration, history tracking, AI fix suggestions |
| **Lifetime** | **$99 once** | Everything in Pro, forever |

**[棣冩啝 Buy Pro / Lifetime](https://xiaohou2503687-design.github.io/guardrail/pricing)**

---

## 棣冨皞 Why GuardRail?

- **Zero config** 閳?works on any project instantly
- **40+ detection rules** 閳?secrets, OWASP, deps, config
- **Offline-first** 閳?no data sent anywhere
- **Open source** 閳?MIT license, audit the code yourself
- **CI/CD ready** 閳?`--json` flag for GitHub Actions

---

## 棣冾檪 Sponsors & Support

鐚?**Star this repo** if you find it useful!

<a href="https://github.com/sponsors/xiaohou2503687-design"><img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-%23db61a2?logo=github"></a>
<a href="https://ko-fi.com/shipfast"><img src="https://img.shields.io/badge/Ko--fi-Buy%20me%20a%20coffee-ff5e5b?logo=ko-fi"></a>

---

<p align="center">
  <sub>Built with 閴傘倧绗?by <a href="https://github.com/xiaohou2503687-design">chunfeng3681</a> | MIT License</sub>
</p>

---

## 🧰 More Tools

- [💰 PayFlow](https://github.com/xiaohou2503687-design/payflow) — Stripe analytics for indie hackers
- [🔍 SEOmatic](https://github.com/xiaohou2503687-design/seomatic) — AI content cluster generator
- [🚀 ShipFast](https://github.com/xiaohou2503687-design/shipfast-oss) — One-command deploy