# AI Security Engineering

A 12-week, hands-on learning repo for securing AI systems: LLM apps, RAG, agents, adversarial ML, red teaming, and secure deployment.

**Cycle:** LEARN → RESEARCH → BUILD A LAB → TEST AN ATTACK → IMPLEMENT DEFENSE → RETEST → DOCUMENT → PUBLISH

> **Scope rule.** Practice only on your own apps, intentionally vulnerable labs, local toy systems, or targets you have written authorization to test. Use synthetic data, mock tools, and test credentials. Never put workplace secrets or customer data into public AI tools.

## Goals

By week 12 you can, for any AI feature: explain the vulnerability, reproduce it safely, identify the root cause, fix it at the right control boundary, and prove the change with a repeatable test.

## Prerequisites

- Python 3.11+, Git, a virtualenv. Docker optional.
- Working knowledge of FastAPI, LLM APIs, RAG and agents.
- 8–10 hours per week (Read 2h, Watch 1–2h, Build 3–4h, Document 1h).

## Setup

```bash
git clone <your-fork-url> ai-security-engineering
cd ai-security-engineering
python -m venv .venv && source .venv/bin/activate
pip install -r labs/lab-01-web-security/requirements.txt
cp labs/lab-01-web-security/.env.example labs/lab-01-web-security/.env   # local test values only
pytest labs/lab-01-web-security -q
```

Never commit `.env`. Only `.env.example` is tracked.

## 12-week checklist

- [ ] **W1** Cybersecurity & networking foundations. Lab 01 (auth + RBAC) ← *chapter and lab included*
- [ ] **W2** Web/API vulnerabilities for AI products (BOLA, SQLi, SSRF…) ← *chapter and lab extension included*
- [ ] **W3** AI threat modeling & frameworks
- [ ] **W4** LLM fundamentals & prompt injection. Lab 02
- [ ] **W5** LLM app risks & defensive design
- [ ] **W6** RAG & retrieval security. Lab 03
- [ ] **W7** Agent & tool security. Lab 04
- [ ] **W8** LLM red teaming & automated evaluation
- [ ] **W9** Adversarial machine learning
- [ ] **W10** Model & AI supply-chain security
- [ ] **W11** Production defenses, monitoring, incident response
- [ ] **W12** Capstone: AI Security Evaluator

## Repository map

| Path | Purpose |
|---|---|
| `ROADMAP.md` | Weekly outcomes, hours, reading, video, lab, deliverable |
| `resources/` | Source catalogue (docs, videos) with verification status |
| `templates/` | topic-notes, lab-report, threat-model |
| `00-foundations/` … `07-secure-deployment/` | Weekly chapters (only Weeks 1–2 written so far) |
| `labs/` | Runnable, isolated labs with tests |
| `projects/ai-security-evaluator/` | Capstone |

## Per-vulnerability record

asset → trust boundary → attacker capability → preconditions → reproduction → impact → root cause → mitigation → regression test → remaining risk

## Status honesty

- Only Weeks 1–2 content exists. Later weeks are outlined in `ROADMAP.md`, not written.
- `resources/` marks each link as *verified*, *carried from your roadmap (unverified)*, or *search link*. Do not treat unverified links as checked.
- Test results in lab reports are recorded only when actually run.

## Portfolio outcomes

Public repo, three lab reports, a threat model + diagram, a before/after evaluation report, and a README demo (threat, proof, fix, verification, limitations).
