"""Level 3 - Report generation.

Reads the raw reports of every scanner and writes one normalized report:
  summary.json  (read by the Security Gate, level 4)
  security-report.md / security-report.html  (for humans)

Usage: python scripts/security_report.py <reports-dir> <output-dir>
"""
import html
import json
import os
import sys
from datetime import datetime, timezone

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


def load(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8-sig") as f:  # -sig: tolerate a BOM written by Windows tools
        text = f.read().strip()
    return json.loads(text) if text else None


def finding(rule, severity, location, title, cvss=None, fixed_in=None):
    return {
        "rule": rule,
        "severity": (severity or "UNKNOWN").upper(),
        "location": location,
        "title": title,
        "cvss": cvss,
        "fixed_in": fixed_in,
    }


def parse_gitleaks(data):
    # Every leaked secret is treated as CRITICAL: it must be revoked, not just removed.
    return [finding(f.get("RuleID"), "CRITICAL", f"{f.get('File')}:{f.get('StartLine')}",
                    f.get("Description") or "Secret detected") for f in data or []]


def parse_bandit(data):
    return [finding(r["test_id"], r["issue_severity"], f"{r['filename']}:{r['line_number']}",
                    r["issue_text"]) for r in data.get("results", [])]


def parse_sonarqube(data):
    if data.get("quality_gate") == "OK":
        return []
    return [finding("quality-gate", "CRITICAL", "SonarQube project devsecops-project",
                    f"Quality gate 'DevSecOps' status: {data.get('quality_gate')}")]


def best_cvss(vuln):
    scores = [v.get("V3Score") for v in (vuln.get("CVSS") or {}).values() if v.get("V3Score")]
    return max(scores) if scores else None


def parse_trivy(data):
    out = []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            out.append(finding(
                v["VulnerabilityID"], v.get("Severity"),
                f"{result.get('Target')} ({v.get('PkgName')} {v.get('InstalledVersion')})",
                v.get("Title") or v["VulnerabilityID"], best_cvss(v), v.get("FixedVersion") or None))
    return out


def parse_checkov(data):
    # Checkov prints one object per framework, or a list when several frameworks ran.
    out = []
    for block in data if isinstance(data, list) else [data]:
        for c in (block.get("results") or {}).get("failed_checks", []):
            lines = c.get("file_line_range") or ["?"]
            out.append(finding(c["check_id"], c.get("severity") or "HIGH",
                               f"{c.get('file_path', '').lstrip('/')}:{lines[0]}", c.get("check_name")))
    return out


TOOLS = {
    "gitleaks": ("gitleaks-report.json", parse_gitleaks),
    "bandit": ("bandit-report.json", parse_bandit),
    "sonarqube": ("sonarqube-result.json", parse_sonarqube),
    "trivy-fs": ("trivy-fs.json", parse_trivy),
    "checkov": ("checkov-report.json", parse_checkov),
    "trivy-image": ("trivy-image.json", parse_trivy),
}


def build_summary(reports_dir):
    tools = {}
    for name, (filename, parser) in TOOLS.items():
        data = load(os.path.join(reports_dir, filename))
        if data is None:
            tools[name] = {"present": False, "findings": []}
            continue
        findings = parser(data)
        findings.sort(key=lambda f: SEVERITIES.index(f["severity"]) if f["severity"] in SEVERITIES else 99)
        tools[name] = {"present": True, "findings": findings}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "commit": os.environ.get("GITHUB_SHA", "local"),
        "tools": tools,
    }


def counts(findings):
    return {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES[:4]}


def to_markdown(summary):
    lines = [f"## Security report - commit `{summary['commit'][:7]}`", "",
             "| Tool | Report | Critical | High | Medium | Low |", "|---|---|---|---|---|---|"]
    for name, t in summary["tools"].items():
        c = counts(t["findings"])
        lines.append(f"| {name} | {'yes' if t['present'] else '**missing**'} | "
                     f"{c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | {c['LOW']} |")
    for name, t in summary["tools"].items():
        if t["findings"]:
            lines += ["", f"### {name}", "", "| Severity | Rule | Location | Title | CVSS | Fixed in |",
                      "|---|---|---|---|---|---|"]
            for f in t["findings"]:
                lines.append(f"| {f['severity']} | {f['rule']} | {f['location']} | {f['title']} | "
                             f"{f['cvss'] or ''} | {f['fixed_in'] or ''} |")
    return "\n".join(lines) + "\n"


def to_html(summary):
    rows = "".join(
        f"<tr><td>{html.escape(n)}</td><td>{'yes' if t['present'] else '<b>missing</b>'}</td>"
        + "".join(f"<td>{v}</td>" for v in counts(t["findings"]).values()) + "</tr>"
        for n, t in summary["tools"].items())
    details = ""
    for n, t in summary["tools"].items():
        if not t["findings"]:
            continue
        body = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(f[k] or ''))}</td>"
                             for k in ("severity", "rule", "location", "title", "cvss", "fixed_in")) + "</tr>"
            for f in t["findings"])
        details += (f"<h2>{html.escape(n)}</h2><table><tr><th>Severity</th><th>Rule</th><th>Location</th>"
                    f"<th>Title</th><th>CVSS</th><th>Fixed in</th></tr>{body}</table>")
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Security report</title><style>"
        "body{font-family:sans-serif;margin:2rem}table{border-collapse:collapse;margin-bottom:1.5rem}"
        "td,th{border:1px solid #ccc;padding:4px 8px;text-align:left}</style></head><body>"
        f"<h1>Security report</h1><p>Commit {html.escape(summary['commit'])} - {summary['generated_at']}</p>"
        "<table><tr><th>Tool</th><th>Report</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>"
        f"{rows}</table>{details}</body></html>")


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    reports_dir, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    summary = build_summary(reports_dir)
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    markdown = to_markdown(summary)
    with open(os.path.join(out_dir, "security-report.md"), "w", encoding="utf-8") as f:
        f.write(markdown)
    with open(os.path.join(out_dir, "security-report.html"), "w", encoding="utf-8") as f:
        f.write(to_html(summary))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(markdown)
    print(markdown)


if __name__ == "__main__":
    main()
