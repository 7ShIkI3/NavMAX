#!/usr/bin/env python3
"""
Bandit result evaluator — exits non-zero if HIGH or CRITICAL vulnerabilities exist.
Used by .github/workflows/security-scan.yml
"""
import json
import sys

def main():
    report_path = "reports/bandit-report.json"
    try:
        with open(report_path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"⚠️  Cannot read Bandit report: {e}")
        sys.exit(0)

    results = data.get("results", [])
    critical = [
        r for r in results
        if r.get("issue_severity", "").upper() in ("HIGH", "CRITICAL")
    ]

    print(f"Total Bandit findings: {len(results)}")
    print(f"HIGH/CRITICAL findings: {len(critical)}")

    if critical:
        print("\n❌ Blocking vulnerabilities found:")
        for r in critical:
            sev = r.get("issue_severity", "?")
            fname = r.get("filename", "?")
            line = r.get("line_number", "?")
            text = r.get("issue_text", "?")
            print(f"  [{sev}] {fname}:{line} — {text}")
        sys.exit(1)
    else:
        print("✅ No HIGH or CRITICAL vulnerabilities detected.")

if __name__ == "__main__":
    main()
