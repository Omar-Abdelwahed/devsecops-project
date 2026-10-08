"""Level 4 - Security Gate.

Applies security-policy.json to the normalized report (summary.json) and decides
BLOCK or PASS. Fails closed: a missing scanner report blocks the pipeline.

Usage: python scripts/security_gate.py <summary.json> <security-policy.json> [--out gate-result.json]
                                       [--skip TOOL ...]   (local runs only, e.g. --skip sonarqube)
Exit code: 0 = PASS, 1 = BLOCK
"""
import argparse
import json
import os
import sys


def is_blocking(f, rule):
    if rule.get("only_fixable") and not f.get("fixed_in"):
        return False  # nothing to upgrade to: reported, not blocking
    if f["severity"] in rule.get("block_severities", []):
        return True
    threshold = rule.get("block_cvss_at_or_above")
    return threshold is not None and f.get("cvss") is not None and f["cvss"] >= threshold


def evaluate(summary, policy, skip=()):
    results = []
    for name, rule in policy["tools"].items():
        if name in skip:
            results.append({"tool": name, "label": rule["label"], "status": "SKIPPED",
                            "reason": "skipped for this local run", "blocking": []})
            continue
        tool = summary["tools"].get(name, {"present": False, "findings": []})
        if not tool["present"]:
            missing = policy.get("fail_if_report_missing", True)
            results.append({"tool": name, "label": rule["label"], "status": "BLOCK" if missing else "PASS",
                            "reason": "report missing (scanner did not run or crashed)", "blocking": []})
            continue
        blocking = [f for f in tool["findings"] if is_blocking(f, rule)]
        results.append({
            "tool": name, "label": rule["label"], "status": "BLOCK" if blocking else "PASS",
            "reason": f"{len(blocking)} blocking / {len(tool['findings'])} reported",
            "blocking": blocking})
    return results


def main():
    parser = argparse.ArgumentParser(description="Security Gate")
    parser.add_argument("summary")
    parser.add_argument("policy")
    parser.add_argument("--out")
    parser.add_argument("--skip", nargs="*", default=[])
    args = parser.parse_args()
    with open(args.summary, encoding="utf-8") as f:
        summary = json.load(f)
    with open(args.policy, encoding="utf-8") as f:
        policy = json.load(f)

    results = evaluate(summary, policy, args.skip)
    decision = "BLOCK" if any(r["status"] == "BLOCK" for r in results) else "PASS"

    lines = [f"## Security Gate: {decision}", "", "| Check | Result | Details |", "|---|---|---|"]
    lines += [f"| {r['label']} | {r['status']} | {r['reason']} |" for r in results]
    for r in results:
        for f in r["blocking"]:
            lines.append(f"- **{r['label']}** {f['severity']} `{f['rule']}` {f['location']}: {f['title']}")
    report = "\n".join(lines) + "\n"
    print(report)

    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"decision": decision, "checks": results}, f, indent=2)
    sys.exit(1 if decision == "BLOCK" else 0)


if __name__ == "__main__":
    main()
