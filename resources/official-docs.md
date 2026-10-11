# Official docs & tools catalogue

**Verification key**
- `reachable` = HTTP 200 on 2026-10-12 (checked with curl). This confirms the URL resolves, **not** that the content matches the description or is the latest version.
- `from roadmap` = description taken from your roadmap; not independently checked.
- Publication dates are not recorded because I did not verify them.

| Resource | Publisher | Why it matters | Weeks | Status |
|---|---|---|---|---|
| [Web Security Academy: Getting started](https://portswigger.net/web-security/getting-started) | PortSwigger | Free interactive web-vuln labs | 1–2 | reachable |
| [OverTheWire Bandit](https://overthewire.org/wargames/bandit/) | OverTheWire | Linux CLI basics via wargame | 1 | reachable |
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | OWASP | Intentionally vulnerable web app (practice only on local instance) | 2 | reachable |
| [Web Security Academy: SQL injection](https://portswigger.net/web-security/sql-injection) | PortSwigger | Free interactive SQLi labs | 2 | reachable |
| [Web Security Academy: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) | PortSwigger | Free interactive XSS labs | 2 | reachable |
| [Web Security Academy: SSRF](https://portswigger.net/web-security/ssrf) | PortSwigger | Free interactive SSRF labs | 2 | reachable |
| [Web Security Academy: File path traversal](https://portswigger.net/web-security/file-path-traversal) | PortSwigger | Free interactive path-traversal labs | 2 | reachable |
| [Web Security Academy: Access control](https://portswigger.net/web-security/access-control) | PortSwigger | Free interactive BOLA/IDOR and broken access-control labs | 1–2 | reachable |
| [OWASP GenAI LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | OWASP GenAI Security Project | LLM risk taxonomy. Your roadmap says the site lists a 2026 release; **check the live page for current risk names before citing** | 3,5,6,10 | reachable |
| [OWASP AI Exchange](https://owasp.org/projects/ai-exchange) | OWASP | AI security controls guidance | 5,10 | reachable |
| [MITRE ATLAS](https://atlas.mitre.org/) | MITRE | Adversary tactics/techniques for AI | 3,9 | reachable |
| [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) | NIST | Risk-management framework | 3,11 | reachable |
| [NIST AI 600-1 GenAI Profile (PDF)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) | NIST | GenAI-specific risk profile | 3 | reachable |
| [Google SAIF](https://saif.google/) | Google | Secure AI framework, risks/controls | 3,5,7,10 | reachable |
| [Microsoft AI Red Team](https://learn.microsoft.com/en-us/security/ai-red-team/) | Microsoft | Red-team practice guidance | 7,11 | reachable |
| [PyRIT](https://microsoft.github.io/PyRIT/latest/) | Microsoft | Red-teaming automation framework | 7,8 | reachable |
| [garak](https://docs.garak.ai/) | NVIDIA | LLM vulnerability scanner | 8 | reachable |
| [Promptfoo red-team quickstart](https://www.promptfoo.dev/docs/red-team/quickstart/) | Promptfoo | Eval + red-team config | 6,8,11 | reachable |
| [Adversarial Robustness Toolbox](https://adversarial-robustness-toolbox.readthedocs.io/) | ART maintainers | Adversarial ML library; pin versions | 9 | reachable |

Reminder: scanners (PyRIT, garak, Promptfoo) only against your own mock targets or authorized endpoints.

## Gaps to fill before the relevant week
- Primary research papers (prompt injection, poisoning, extraction) are **not yet curated**. I will add them per week from searched sources rather than from memory.
- Specific GitHub repos beyond the tools above: pending.
