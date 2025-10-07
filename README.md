# BypassLab — Practical Security Playbooks & PoCs

**Owner:** adce626  
**Repo:** BypassLab-PoC — concise, practical playbooks and minimal PoCs for common web security issues (SSTI, IDOR, password reset, payment bypasses, subscription logic).

## About
This repository collects short, tactical, no‑fluff security playbooks and reproducible PoCs intended for authorized testing (CTF / staging / pentest in‑scope). Each document is designed to be PoC‑ready: what to test → why it matters → quick PoC/observables → mitigation. Use responsibly; do not test production without permission.

## Files (examples)
- `Account_Takeover_Password_Reset_OmniWatch_adce626.md` — email payloads & practical test plan for password reset takeover.  
- `Password_Reset_Testing_Checklist.md` — concise checklist for password reset flows.  
- `SSTI_Bypass_Checklist.md` — SSTI detection & bypass playbook with minimal PoCs.  
- `Payment-Amount_403-Bypass.md` — payment amount tampering & 403 bypass techniques.  
- `Subscription_Model_Testing_Checklist.md` — subscription plan testing, webhook checks, trial abuse.  
- `IDOR & 403 Bypass Payloads Cheat‑Sheet.md` — payload cheat‑sheet for IDOR/403 bypass tests.  
- Other supporting files: short PoCs, automation snippets, and lab configs.



2. Read the relevant playbook (Markdown). Each file contains curl/Burp examples you can run in a staging lab.

3. Use safe tooling: Burp Suite, Python requests, `curl`, `wfuzz`/`ffuf`, and a catch‑all mail service for email tests. Never run tests against production without written permission.

## Contribution & usage
- Contributions: send a PR with a focused, reproducible playbook or PoC. Keep it short and include minimal repro steps and mitigations.  
- Issues: use GitHub Issues to report typos or suggest new playbooks.  
- License: add a LICENSE file to the repo (recommended: MIT for community sharing or choose a policy that fits your organization).

## Responsible disclosure
This content is for authorized security testing and learning only. Do not use these materials for unauthorized testing. If you discover real vulnerabilities, follow responsible disclosure and report them to the affected organization or through a bug bounty program.

---
**Contact / alias:** adce626 — use GitHub for PRs or issues.  
**Tagline:** BypassLab — Practical, PoC‑ready security playbooks.

