# ROADMAP

Baseline: your "AI Security Engineering: 12-Week Roadmap". Sequencing is unchanged. One addition: every week ends with a short self-assessment and a "regression test" requirement.

Hours per week: ~8–10 (Read 2 · Watch 1–2 · Build 3–4 · Document 1).

| Wk | Topic | Prereq | Reading | Video | Lab | Deliverable |
|---|---|---|---|---|---|---|
| 1 | Foundations: CIA, HTTP, authN vs authZ | Python, FastAPI | PortSwigger getting started; OverTheWire Bandit (basics) | HTTP/web-security fundamentals (search link) | `labs/lab-01-web-security` | `00-foundations/http-api-security.md` + auth tests |
| 2 | Web/API vulns: BOLA/IDOR, SQLi, XSS, SSRF, path traversal | W1 | PortSwigger topics; OWASP Juice Shop | PortSwigger beginner labs (search link) | Patch toy API: validation, parameterized queries, authZ | One lab report (vuln, impact, patch, regression test) |
| 3 | AI threat modeling & frameworks | W1–2 | OWASP GenAI Top 10; MITRE ATLAS; NIST AI RMF + AI 600-1; Google SAIF | IBM OWASP LLM explainer (older) | Threat-model a toy chatbot/RAG app | `01-threat-modeling/llm-app-threat-model.md` + Mermaid |
| 4 | LLM basics & prompt injection | W3 | OWASP GenAI videos | MS "AI Red Teaming 101" Ep 1–7 | `lab-02`: mock-secret chatbot + attack suite | `02-llm-security/prompt-injection.md`, dataset, failure table |
| 5 | LLM app risks & defensive design | W4 | OWASP LLM Top 10; AI Exchange | OWASP LLM secure design (search link) | Schema-validated output, authZ outside model, limits | Hardened chatbot + test report |
| 6 | RAG & retrieval security | W4–5 | OWASP; Promptfoo red-team guide | RAG security (search link) | `lab-03`: two-tenant RAG, poisoned doc | `03-rag-security/` |
| 7 | Agent & tool security | W5–6 | SAIF; MS AI Red Team; PyRIT docs | AI Red Teaming 101 Ep 4, 7, 8–10 | `lab-04`: mock tools, approval gate, audit log | Permissioned toy agent + tests |
| 8 | Red teaming & automated eval | W4–7 | PyRIT; garak; Promptfoo | garak tutorial (search link) | Run one tool against a mock target | `05-ai-red-teaming/` plan + run report |
| 9 | Adversarial ML | W3 | MITRE ATLAS; ART docs | Adversarial ML (search link) | Toy classifier evasion | `06-adversarial-ml/evasion-lab.ipynb` |
| 10 | Supply chain | W5 | OWASP; SAIF; AI Exchange | Supply-chain security (search link) | Pinning, secret scan, non-root container, CI | `07-secure-deployment/supply-chain-checklist.md` + CI |
| 11 | Production defenses & IR | W5–10 | NIST AI RMF; MS AI Red Team | Monitoring/IR (search link) | Structured security events, log redaction | Runbook + log-redaction test |
| 12 | Capstone: AI Security Evaluator | All | – | – | Evaluator against your toy app | Before/after report, README demo |

## Completion criteria (each week)

1. You can explain the topic without notes.
2. A minimal reproduction exists in the lab.
3. Root cause and control boundary are written down.
4. A defense is implemented and a test would catch its regression.
5. Limitations / residual risk are stated.

## Capstone spec (Week 12) — summary

Target: your own local FastAPI chatbot/RAG/agent. Categories: prompt injection, sensitive data, authorization, unsafe tool use, output validation, resource limits, benign false-positive checks. Per test store: ID, objective, setup, input, expected, observed, pass/fail, severity, evidence, remediation. Output a Markdown or HTML report; rerun after fixes and diff. Start with pytest + deterministic mocks, then add one of Promptfoo / garak / PyRIT. Include scope statement, safe-use warning, known limitations.

Weeks 2–12 chapters will be written one at a time as you finish and test the previous one.
