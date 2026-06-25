#!/usr/bin/env python3
"""
detect-secrets result evaluator — exits non-zero if high-confidence secrets found.
Used by .github/workflows/security-scan.yml
"""
import json
import sys


def main():
    report_path = "reports/detect-secrets-report.json"
    try:
        with open(report_path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"⚠️  Cannot read detect-secrets report: {e}")
        sys.exit(0)

    results = data.get("results", {})
    total = sum(len(v) for v in results.values())

    high_conf = []
    for fname, secrets in results.items():
        for s in secrets:
            if s.get("is_secret") and s.get("confidence", "").upper() in ("HIGH", "VERY_HIGH"):
                high_conf.append((fname, s))

    print(f"📊 Total potential secrets: {total}")
    print(f"⚠️  High-confidence secrets: {len(high_conf)}")

    if high_conf:
        print("\n❌ High-confidence secrets detected — review required:")
        for fname, s in high_conf:
            line = s.get("line_number", "?")
            stype = s.get("type", "?")
            conf = s.get("confidence", "?")
            print(f"  [{conf}] {fname}:{line} — {stype}")
        sys.exit(1)
    else:
        print("✅ No high-confidence secrets found.")


if __name__ == "__main__":
    main()
