# Mini-VulnFinBot — Secure CI/CD Pipeline with AI-Specific Security Controls

Lab 5 · AI for Cybersecurity · Madi Zhatkanbayev

Mini-VulnFinBot is a small AI financial assistant (Flask REST API). Every push runs a GitHub Actions
pipeline that tests the code, its dependencies, its container image, the running service and its
AI-specific behaviour, then publishes every report as a build artifact.

## Technologies

| Area | Tool |
| --- | --- |
| App | Python 3.12, Flask 3.1, gunicorn |
| Tests | pytest (API tests + AI security tests) |
| SAST | Bandit, Semgrep with custom rules (`security/semgrep/rules.yml`) |
| Dependencies | pip-audit |
| Container | Docker (`python:3.12-slim`, non-root), Trivy |
| DAST | OWASP ZAP baseline |
| LLM (optional) | Ollama — `qwen2.5:0.5b` in CI |
| CI/CD | GitHub Actions + artifacts |

## Architecture

```
POST /api/chat
   │
   ├─ routes.py      request validation: JSON object, "message" string, 1–1000 chars, 16 KB body
   │
   └─ assistant.py
        1. input_guard     prompt-injection heuristics (LLM01)            → refuse + flag
        2. model           NaiveMockModel (default) or OllamaModel
        3. run_tool        allow-list + account bound to session (LLM06, LLM02)
        4. output_guard    prompt-leak canary, secret/PII redaction,
                           HTML escaping, external-image removal (LLM07, LLM02, LLM05)
   │
   └─ JSON {"response": ..., "security_flags": [...]}   + security headers on every response
```

Security decisions are made in code, never by the model. The default mock model is deliberately
*naive* — it obeys every instruction — so the tests prove the controls hold even when the model fails.

## Run locally

```bash
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt
python run.py                       # http://127.0.0.1:5000
curl localhost:5000/health
curl -X POST localhost:5000/api/chat -H 'Content-Type: application/json' \
     -d '{"message": "How can I manage my monthly budget?"}'
```

With a real model: `ollama pull qwen2.5:0.5b && LLM_BACKEND=ollama python run.py`

Docker:

```bash
docker build -t vulnfinbot:latest .
docker run --rm -p 5000:5000 vulnfinbot:latest
```

## Tests

```bash
pytest -v                                     # 48 tests; 4 of them need a real LLM and skip without Ollama
LLM_BACKEND=ollama pytest tests/test_ai_security.py -v   # against a real model
```

`tests/test_ai_security.py` writes `reports/ai-security-report.md` automatically.

## Security scans (local)

```bash
mkdir -p reports
bandit -r app/ run.py -f json -o reports/bandit-report.json
semgrep scan --config security/semgrep/rules.yml --metrics=off --json --output reports/semgrep-report.json app/ run.py
pip-audit -r requirements.txt -f json -o reports/dependency-report.json
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/reports:/reports" \
  aquasec/trivy:0.58.1 image --format json --output /reports/trivy-report.json vulnfinbot:latest
docker run --rm --network host -v "$PWD/reports:/zap/wrk/:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000 -J zap-report.json -I
python security/summarize.py --reports reports --gate
```

## CI/CD pipeline (`.github/workflows/security-pipeline.yml`)

Runs on push to `main`/`vuln-demo`, on pull requests to `main`, and manually.

| Job | Steps |
| --- | --- |
| `tests` | checkout → Python 3.12 → install → `pytest -v` (API + AI security) |
| `security` | tests → Bandit → Semgrep → pip-audit → `docker build` → Trivy → start container → OWASP ZAP baseline → summary + gate → upload `vulnfinbot-security-reports` |
| `ai-llm` | Ollama container + `qwen2.5:0.5b` → AI security tests against a real model → upload `ai-security-report-llm` (informational) |

Each scanner step uses `continue-on-error`, and upload steps use `if: always()`, so one failing
scanner never stops later reports from being uploaded. The final gate step fails the job on any
blocking finding: Bandit HIGH, Semgrep ERROR, a known-vulnerable dependency, a fixable HIGH/CRITICAL
Trivy CVE, a ZAP HIGH alert, or a failed test.

## Getting the reports

Actions → latest *Security CI Pipeline* run → **Artifacts** → `vulnfinbot-security-reports`:
`bandit-report.json`, `semgrep-report.json`, `dependency-report.json`, `trivy-report.json`,
`zap-report.json` / `.html`, `ai-security-report.md`, `pytest-report.xml`, `security-summary.md`.
The summary table is also shown on the run's Summary page.

## Vulnerability demonstration (`vuln-demo` branch)

The `vuln-demo` branch plants 16 controlled flaws (`app/insecure_demo.py` plus edits) to prove the
pipeline catches them. **Never merge it.**

| Tool | `vuln-demo` (before) | `main` (after fix) |
| --- | --- | --- |
| Bandit | 11 issues (4 HIGH, 5 MEDIUM, 2 LOW) | 0 |
| Semgrep | 15 findings (8 ERROR) | 0 |
| pip-audit | 26 known vulnerabilities | 0 |
| AI security tests | 14/19 passed, 4 failed | 18/19 passed, 1 accepted residual risk |
| Gate | FAIL | PASS |

Remediation: delete the insecure endpoints; restore localhost binding and `debug=False`; remove
`send_email` from the tool allow-list; restore HTML escaping of model output; upgrade Flask 2.2.0 →
3.1.3, Werkzeug 2.2.2 → 3.1.9, requests 2.25.1 → 2.34.2.

## Known limitations

- The regex input guard can be bypassed by paraphrasing (test T1.4). The impact is limited because
  tools and output are enforced in code. Next step: an ML prompt-injection classifier.
- The mock model cannot show how a real LLM resists injection; the `ai-llm` job covers that.
- ZAP baseline is passive. It does not replace a penetration test.
- Only fake data is used. There are no real customer records or credentials anywhere.
