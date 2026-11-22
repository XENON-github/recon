#!/usr/bin/env python3
"""Warn about expired or soon-to-expire TLS certificates in a recon JSON report.

    recon app.example.lan -p 443,8443 --json -q -o scan.json
    python3 scripts/cert_expiry.py scan.json --days 30

Exit codes: 0 = nothing expiring, 1 = at least one certificate expired or expiring within --days,
2 = bad input, or the report holds no certificate data (recon built without OpenSSL, or no TLS ports).
"""
import argparse, datetime, json, sys


def parse_not_after(text):
    # OpenSSL prints e.g. "Jan  1 00:00:00 2030 GMT" (day padded with spaces).
    return datetime.datetime.strptime(" ".join(text.split()), "%b %d %H:%M:%S %Y GMT").replace(tzinfo=datetime.timezone.utc)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report")
    ap.add_argument("--days", type=int, default=30, help="warn when a certificate expires within this many days (default 30)")
    a = ap.parse_args()
    try:
        with open(a.report, encoding="utf-8") as f:
            doc = json.load(f)
        hosts = doc["hosts"]
    except (OSError, ValueError, KeyError) as e:
        print(f"cert_expiry: cannot read report: {e}", file=sys.stderr)
        return 2

    now = datetime.datetime.now(datetime.timezone.utc)
    seen = bad = 0
    for h in hosts:
        for p in h.get("ports", []):
            tls = p.get("service", {}).get("tls")
            cert = tls.get("certificate") if isinstance(tls, dict) else None
            if not isinstance(cert, dict):
                continue
            seen += 1
            try:
                left = (parse_not_after(cert["not_after"]) - now).days
            except (KeyError, ValueError):
                print(f"{h['address']}:{p['port']}  unreadable expiry date", file=sys.stderr)
                bad += 1
                continue
            status = "EXPIRED" if left < 0 else ("EXPIRING" if left <= a.days else "ok")
            note = " self-signed" if cert.get("self_signed") else ""
            print(f"{status:9s} {h['address']}:{p['port']}  {cert.get('subject', '?')}  ({left} days){note}")
            bad += status != "ok"
    if seen == 0:
        print("cert_expiry: no certificate data in this report (no TLS ports, or recon was built without OpenSSL)", file=sys.stderr)
        return 2
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
