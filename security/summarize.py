"""Aggregate all scanner reports into one summary table (Step 10) and apply a security gate.

Usage: python security/summarize.py [--reports reports] [--gate]
Writes reports/security-summary.md and appends it to $GITHUB_STEP_SUMMARY when set.
With --gate, exits 1 when a blocking finding is present.
"""
import argparse
import collections
import json
import os
import pathlib
import re
import xml.etree.ElementTree as ET  # nosec B405 — parses our own pytest JUnit output only


def load(path: pathlib.Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def fmt(counter: dict, order=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) -> str:
    parts = [f"{k}: {counter[k]}" for k in order if counter.get(k)]
    return ", ".join(parts) if parts else "none"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--gate", action="store_true")
    a = ap.parse_args()
    d = pathlib.Path(a.reports)
    rows, blocking = [], []

    # ---- Bandit
    b = load(d / "bandit-report.json")
    if b is None:
        rows.append(("Bandit", "report missing", "-", "Check the Bandit step log"))
    else:
        c = collections.Counter(r["issue_severity"] for r in b.get("results", []))
        ids = sorted({f'{r["test_id"]} {r["test_name"]}' for r in b.get("results", [])})
        rows.append(("Bandit", f'{sum(c.values())} issue(s){": " + "; ".join(ids) if ids else ""}', fmt(c),
                     "Fix HIGH/MEDIUM before merge" if c else "No action"))
        if c.get("HIGH"):
            blocking.append(f'Bandit: {c["HIGH"]} HIGH')

    # ---- Semgrep
    s = load(d / "semgrep-report.json")
    if s is None:
        rows.append(("Semgrep", "report missing", "-", "Check the Semgrep step log"))
    else:
        sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        c = collections.Counter(sev.get(r["extra"]["severity"], "LOW") for r in s.get("results", []))
        ids = sorted({r["check_id"].split(".")[-1] for r in s.get("results", [])})
        rows.append(("Semgrep (custom rules)", f'{sum(c.values())} finding(s){": " + "; ".join(ids) if ids else ""}',
                     fmt(c), "Fix ERROR-level findings before merge" if c else "No action"))
        if c.get("HIGH"):
            blocking.append(f'Semgrep: {c["HIGH"]} ERROR')

    # ---- pip-audit
    p = load(d / "dependency-report.json")
    if p is None:
        rows.append(("pip-audit", "report missing", "-", "Check the pip-audit step log"))
    else:
        vulns = sorted({(dep["name"], dep["version"], v["id"], ",".join(v.get("fix_versions", [])) or "no fix")
                        for dep in p.get("dependencies", []) for v in dep.get("vulns", [])})
        txt = "; ".join(f"{n} {ver} {vid} (fix: {fx})" for n, ver, vid, fx in vulns)
        rows.append(("pip-audit", f"{len(vulns)} vulnerable package version(s){': ' + txt if txt else ''}",
                     "HIGH" if vulns else "none", "Upgrade to the fixed versions" if vulns else "No action"))
        if vulns:
            blocking.append(f"pip-audit: {len(vulns)} known vulnerabilities")

    # ---- Trivy
    t = load(d / "trivy-report.json")
    if t is None:
        rows.append(("Trivy", "report missing (runs in CI)", "-", "See the GitHub Actions artifact"))
    else:
        c, by_class, fixable_high = collections.Counter(), collections.Counter(), 0
        for res in t.get("Results", []) or []:
            for v in res.get("Vulnerabilities", []) or []:
                c[v["Severity"]] += 1
                by_class[res.get("Class", "?")] += 1
                if v["Severity"] in ("CRITICAL", "HIGH") and v.get("FixedVersion"):
                    fixable_high += 1
        detail = ", ".join(f"{k}: {n}" for k, n in by_class.items()) or "no vulnerabilities"
        rows.append(("Trivy (image)", f"{sum(c.values())} CVE(s) [{detail}]; {fixable_high} HIGH/CRITICAL with a fix",
                     fmt(c), "Rebuild on patched base / upgrade packages with fixes; track unfixed OS CVEs"))
        if fixable_high:
            blocking.append(f"Trivy: {fixable_high} fixable HIGH/CRITICAL")

    # ---- OWASP ZAP
    z = load(d / "zap-report.json")
    if z is None:
        rows.append(("OWASP ZAP baseline", "report missing (runs in CI)", "-", "See the GitHub Actions artifact"))
    else:
        risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
        c, names = collections.Counter(), []
        for site in z.get("site", []):
            for al in site.get("alerts", []):
                c[risk.get(str(al.get("riskcode")), "INFO")] += 1
                names.append(f'{al.get("name")} ({risk.get(str(al.get("riskcode")))})')
        rows.append(("OWASP ZAP baseline", f"{sum(c.values())} alert type(s){': ' + '; '.join(names) if names else ''}",
                     fmt(c), "Fix MEDIUM+ alerts; review LOW/INFO" if c else "No action"))
        if c.get("HIGH"):
            blocking.append(f'ZAP: {c["HIGH"]} HIGH')

    # ---- AI security tests
    ai = d / "ai-security-report.md"
    if ai.exists():
        m = re.search(r"\*\*(\d+)/(\d+) scenarios passed\*\*", ai.read_text(encoding="utf-8"))
        accepted = ai.read_text(encoding="utf-8").count("accepted residual risk")
        if m:
            ok, total = int(m.group(1)), int(m.group(2))
            hard_fail = total - ok - accepted
            rows.append(("AI security tests", f"{ok}/{total} passed; {accepted} accepted residual risk; {hard_fail} failed",
                         "HIGH" if hard_fail else ("LOW" if accepted else "none"),
                         "Fix failing controls" if hard_fail else "Add ML injection classifier for paraphrased attacks"))
            if hard_fail:
                blocking.append(f"AI tests: {hard_fail} failed")
    else:
        rows.append(("AI security tests", "report missing", "-", "Check the AI test step log"))

    junit = d / "pytest-report.xml"
    if junit.exists():
        r = ET.parse(junit).getroot()
        suite = r if r.tag == "testsuite" else r.find("testsuite")
        failures = int(suite.get("failures", 0)) + int(suite.get("errors", 0))
        rows.insert(0, ("Unit tests (pytest)", f'{suite.get("tests")} tests, {failures} failed, {suite.get("skipped")} skipped',
                        "HIGH" if failures else "none", "Fix failing tests" if failures else "No action"))
        if failures:
            blocking.append(f"pytest: {failures} failed")

    out = ["## Security summary — Mini-VulnFinBot", "",
           "| Security Tool | Findings | Severity | Recommended Action |", "| --- | --- | --- | --- |"]
    out += ["| " + " | ".join(str(x).replace("|", "/") for x in row) + " |" for row in rows]
    out += ["", f"**Gate:** {'FAIL — ' + '; '.join(blocking) if blocking else 'PASS — no blocking findings'}"]
    text = "\n".join(out) + "\n"
    (d / "security-summary.md").write_text(text, encoding="utf-8")
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(text)
    print(text)
    return 1 if (a.gate and blocking) else 0


if __name__ == "__main__":
    raise SystemExit(main())
