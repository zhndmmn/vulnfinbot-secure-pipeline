"""Collects AI-security test outcomes and writes reports/ai-security-report.md (Step 9.3)."""
import datetime as dt
import os
import pathlib

import pytest

RESULTS: list[dict] = []


@pytest.fixture
def record():
    def _record(scenario: dict, actual: str, passed: bool, note: str = ""):
        RESULTS.append({**scenario, "actual": actual, "passed": passed, "note": note})
    return _record


def _cell(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


def _code(s: str) -> str:
    # literal text (payloads, raw responses) shown exactly, as inline code
    return "`" + str(s).replace("`", "'").replace("|", "\\|").replace("\n", " ") + "`"


def pytest_sessionfinish(session, exitstatus):
    if not RESULTS:
        return
    backend = os.getenv("LLM_BACKEND", "mock")
    model = os.getenv("OLLAMA_MODEL", "") if backend == "ollama" else "NaiveMockModel (obeys every instruction)"
    default = "reports/ai-security-report.md" if backend == "mock" else "reports/ai-security-report-llm.md"
    path = pathlib.Path(os.getenv("AI_REPORT_PATH", default))
    path.parent.mkdir(parents=True, exist_ok=True)

    passed = sum(r["passed"] for r in RESULTS)
    lines = [
        "# AI Security Test Report — Mini-VulnFinBot",
        "",
        f"- Generated: {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC}",
        f"- Model backend: `{backend}` — {model}",
        f"- Result: **{passed}/{len(RESULTS)} scenarios passed**",
        "",
        "Layer key: **App** = application control, proven with the mock model;"
        " **LLM** = model behaviour, meaningful only with a real model.",
        "",
        "| ID | Scenario | Risk (OWASP) | Layer | Test input | Expected behaviour | Actual behaviour | Result | Mitigation |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in RESULTS:
        verdict = "PASS" if r["passed"] else ("FAIL (accepted residual risk)" if r.get("residual") else "FAIL")
        actual = r["actual"] + (f" — {r['note']}" if r["note"] else "")
        lines.append("| " + " | ".join([
            _cell(r["id"]), _cell(r["scenario"]), _cell(r["risk"]), _cell(r["layer"]), _code(r["input"][:120]),
            _cell(r["expected"]), _code(actual[:220]), _cell(verdict), _cell(r["mitigation"])]) + " |")
    lines += ["", "## Notes", "",
              "- The mock model is deliberately compliant: it leaks its prompt, asks for other customers' data and echoes HTML."
              " Passing results with it show the application controls hold even if the model fails completely.",
              "- A mock cannot show how a real LLM resists prompt injection. The `ai-llm` CI job reruns these scenarios"
              " against a real local model (Ollama) and writes `ai-security-report-llm.md`.",
              "- Only fake data is used. No real customer information or credentials exist in this project."]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
