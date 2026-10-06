"""SOC Sentinel Lab: detect suspicious authentication activity from JSONL logs."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


RULES = {
    "brute_force": {"severity": "high", "technique": "T1110 - Brute Force"},
    "success_after_failures": {"severity": "critical", "technique": "T1110 - Brute Force / T1078 - Valid Accounts"},
    "impossible_travel": {"severity": "high", "technique": "T1078 - Valid Accounts"},
    "privileged_login": {"severity": "medium", "technique": "T1078 - Valid Accounts"},
}


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_events(path: Path) -> list[dict]:
    events = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            event["timestamp"] = parse_time(event["timestamp"])
            events.append(event)
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            raise ValueError(f"Invalid event on line {line_number}: {exc}") from exc
    return sorted(events, key=lambda event: event["timestamp"])


def alert(rule: str, timestamp: datetime, title: str, evidence: dict, recommendation: str) -> dict:
    return {
        "alert_time_utc": timestamp.isoformat().replace("+00:00", "Z"),
        "rule": rule,
        "severity": RULES[rule]["severity"],
        "mitre_attack": RULES[rule]["technique"],
        "title": title,
        "evidence": evidence,
        "recommended_action": recommendation,
    }


def detect(events: list[dict]) -> list[dict]:
    alerts = []
    failed_by_ip: dict[str, list[dict]] = defaultdict(list)
    failed_by_user_ip: dict[tuple[str, str], list[dict]] = defaultdict(list)
    successful_by_user: dict[str, list[dict]] = defaultdict(list)
    emitted_bruteforce: set[tuple[str, str]] = set()

    for event in events:
        now = event["timestamp"]
        ip = event["source_ip"]
        user = event["user"]

        if event["outcome"] == "failure":
            failed_by_ip[ip].append(event)
            failed_by_ip[ip] = [item for item in failed_by_ip[ip] if now - item["timestamp"] <= timedelta(minutes=10)]
            failed_by_user_ip[(user, ip)].append(event)
            failed_by_user_ip[(user, ip)] = [item for item in failed_by_user_ip[(user, ip)] if now - item["timestamp"] <= timedelta(minutes=15)]

            marker = (ip, now.strftime("%Y-%m-%dT%H:%M"))
            if len(failed_by_ip[ip]) >= 5 and marker not in emitted_bruteforce:
                emitted_bruteforce.add(marker)
                alerts.append(alert(
                    "brute_force", now, f"Possible brute-force activity from {ip}",
                    {"source_ip": ip, "failed_attempts": len(failed_by_ip[ip]), "window_minutes": 10,
                     "targeted_users": sorted({item["user"] for item in failed_by_ip[ip]})},
                    "Block or rate-limit the source IP, review targeted accounts, and validate whether failures were expected.",
                ))
            continue

        # Successful events
        recent_failures = [item for item in failed_by_user_ip[(user, ip)] if now - item["timestamp"] <= timedelta(minutes=15)]
        if len(recent_failures) >= 3:
            alerts.append(alert(
                "success_after_failures", now, f"Successful login after repeated failures: {user}",
                {"user": user, "source_ip": ip, "prior_failures": len(recent_failures), "country": event["country"]},
                "Reset the account password, revoke active sessions, and confirm the login with the account owner.",
            ))

        for previous in successful_by_user[user]:
            interval = now - previous["timestamp"]
            if interval <= timedelta(minutes=60) and previous["country"] != event["country"]:
                alerts.append(alert(
                    "impossible_travel", now, f"Potential impossible travel for {user}",
                    {"user": user, "previous_country": previous["country"], "new_country": event["country"],
                     "travel_window_minutes": round(interval.total_seconds() / 60), "source_ip": ip},
                    "Verify the sign-in with the user; if unrecognized, revoke sessions and reset credentials.",
                ))
                break

        if event.get("role") == "admin":
            alerts.append(alert(
                "privileged_login", now, f"Privileged account login: {user}",
                {"user": user, "source_ip": ip, "country": event["country"], "role": "admin"},
                "Confirm the activity is authorized and review privileged actions from this session.",
            ))
        successful_by_user[user].append(event)

    priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(alerts, key=lambda item: (priority[item["severity"]], item["alert_time_utc"]))


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect suspicious authentication activity from JSONL logs.")
    parser.add_argument("--input", required=True, type=Path, help="Path to JSONL authentication events")
    parser.add_argument("--output", required=True, type=Path, help="Where to write alerts as JSON")
    args = parser.parse_args()

    alerts = detect(load_events(args.input))
    args.output.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print(f"Processed logs and wrote {len(alerts)} alert(s) to {args.output}")


if __name__ == "__main__":
    main()
