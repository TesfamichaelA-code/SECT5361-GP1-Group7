#!/usr/bin/env python3
"""SECT5361 GP1 log analysis tool - Group 7.

Reads the three CSV evidence files (read-only), converts every timestamp to
UTC and EAT, merges them into one timeline, flags suspicious events with three
detection rules and verifies the files' SHA-256 hashes.

Usage:
    python3 gp1_tool.py logs/           analyse and verify hashes
    python3 gp1_tool.py logs/ --full    also print every event
    python3 gp1_tool.py logs/ --init    record hashes once, at collection
"""
import argparse
import csv
import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

LOG_FILES = ["auth_logs.csv", "mail_audit.csv", "finance_gateway.csv"]
HASH_FILE = "hashes.sha256"
HEADERS = ["timestamp", "timezone", "source", "user", "event", "detail"]
ZONES = {"UTC": timezone.utc, "EAT": timezone(timedelta(hours=3))}  # EAT = UTC+3

SUSPICIOUS_IP = "185.220.101.45"
WIRE_LIMIT_USD = 100_000


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_detail(detail):
    """'ip=1.2.3.4; amount=500' -> {'ip': '1.2.3.4', 'amount': '500'}"""
    pairs = (part.split("=", 1) for part in detail.split("; ") if "=" in part)
    return {key: value for key, value in pairs}


def load_events(log_dir):
    """Read every row of the three CSV files. Files are opened read-only."""
    events = []
    for name in LOG_FILES:
        path = log_dir / name
        if not path.exists():
            sys.exit(f"Missing evidence file: {path}")
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames != HEADERS:
                sys.exit(f"{name}: headers must be {','.join(HEADERS)}")
            for row in reader:
                row["file"] = name
                events.append(row)
    return events


def to_utc_and_eat(event):
    """Add 'utc' and 'eat' datetimes, whatever zone the row was logged in."""
    if event["timezone"] not in ZONES:
        sys.exit(f"{event['file']}: unknown timezone '{event['timezone']}'")
    logged = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
    utc = logged.replace(tzinfo=ZONES[event["timezone"]]).astimezone(timezone.utc)
    event["utc"] = utc
    event["eat"] = utc.astimezone(ZONES["EAT"])


RULES = {
    "Rule 1": f"Login from suspicious IP {SUSPICIOUS_IP}",
    "Rule 2": "Mailbox rule created (mailbox_rule_created)",
    "Rule 3": f"wire_transfer_approved above USD {WIRE_LIMIT_USD:,}",
}


def apply_rules(event):
    """Return the list of rules this event breaks (empty if none)."""
    info = parse_detail(event["detail"])
    hits = []
    if event["event"].startswith("login") and info.get("ip") == SUSPICIOUS_IP:
        hits.append("Rule 1")
    if event["event"] == "mailbox_rule_created":
        hits.append("Rule 2")
    if event["event"] == "wire_transfer_approved" and float(info.get("amount", 0)) > WIRE_LIMIT_USD:
        hits.append("Rule 3")
    return hits


def line(event):
    return (f"{event['utc']:%Y-%m-%d %H:%M:%S} UTC | {event['eat']:%Y-%m-%d %H:%M:%S} EAT | "
            f"{event['file']:<19} | {event['user']:<30} | {event['event']}")


def print_timeline(events, full):
    shown = events if full else events[:10]
    print(f"\n[2] Merged timeline ({len(shown)} of {len(events)} events"
          f"{'' if full else '; use --full for all'})")
    for event in shown:
        mark = "!!" if event["hits"] else "  "
        print(f"{mark} {line(event)}")


def print_flagged(events):
    flagged = [e for e in events if e["hits"]]
    print("\n[3] Detection rules")
    for rule, description in RULES.items():
        count = sum(rule in e["hits"] for e in events)
        print(f"   {rule}: {description:<45} {count} hit(s)")
    print(f"\n   Flagged events ({len(flagged)}):")
    for event in flagged:
        print(f"!! {line(event)}")
        print(f"   {', '.join(event['hits'])} | {event['detail']}")


def record_hashes(log_dir):
    """Write hashes.sha256 (same format as the sha256sum command). Never overwrites."""
    hash_path = log_dir / HASH_FILE
    if hash_path.exists():
        sys.exit(f"{hash_path} already exists. The baseline is never overwritten.")
    with open(hash_path, "w", encoding="utf-8") as f:
        for name in LOG_FILES:
            f.write(f"{sha256(log_dir / name)}  {name}\n")
    print(f"Recorded SHA-256 hashes in {hash_path}")


def check_hashes(log_dir):
    """Compare each file's current SHA-256 with the hash recorded at collection."""
    print(f"\n[4] SHA-256 verification (against {HASH_FILE})")
    hash_path = log_dir / HASH_FILE
    if not hash_path.exists():
        print(f"   No {HASH_FILE} found. Run with --init at collection time.")
        return False
    recorded = {}
    for entry in hash_path.read_text(encoding="utf-8").splitlines():
        digest, name = entry.split()
        recorded[name] = digest
    all_match = True
    for name in LOG_FILES:
        current = sha256(log_dir / name)
        status = "MATCH" if recorded.get(name) == current else "MISMATCH"
        all_match = all_match and status == "MATCH"
        print(f"   {name:<19} {current}  {status}")
    print("   Result: evidence unchanged since collection." if all_match
          else "   Result: WARNING - evidence has changed since collection!")
    return all_match


def main():
    parser = argparse.ArgumentParser(description="SECT5361 GP1 log analysis tool (Group 7)")
    parser.add_argument("log_dir", type=Path, help="folder containing the 3 CSV files")
    parser.add_argument("--full", action="store_true", help="print every event in the timeline")
    parser.add_argument("--init", action="store_true", help="record the SHA-256 baseline")
    args = parser.parse_args()

    if args.init:
        record_hashes(args.log_dir)
        return

    events = load_events(args.log_dir)
    for event in events:
        to_utc_and_eat(event)
        event["hits"] = apply_rules(event)
    events.sort(key=lambda e: e["utc"])

    print("SECT5361 GP1 - Group 7 log analysis")
    print(f"\n[1] Evidence loaded from {args.log_dir}")
    for name in LOG_FILES:
        print(f"   {name:<19} {sum(e['file'] == name for e in events):>4} events")
    print(f"   {'Total':<19} {len(events):>4} events, "
          f"{events[0]['utc']:%Y-%m-%d %H:%M} to {events[-1]['utc']:%Y-%m-%d %H:%M} UTC")

    print_timeline(events, args.full)
    print_flagged(events)
    if not check_hashes(args.log_dir):
        sys.exit(1)


if __name__ == "__main__":
    main()
