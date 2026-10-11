# Capstone: AI Security Evaluator (Week 12) — spec only

Scope: scan only your own local FastAPI chatbot/RAG/agent. Not for public endpoints.
Test record: id, objective, setup, input, expected, observed, pass/fail, severity, evidence, remediation.
Categories: prompt injection, sensitive data, authorization, unsafe tool use, output validation, resource limits, benign false-positive tests.
Output: Markdown/HTML report; rerun after fixes and diff. Start with pytest + deterministic mocks; add one of Promptfoo / garak / PyRIT later.
Include scope statement, safe-use warning, known limitations. Not implemented yet.
