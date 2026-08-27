"""
Attack Metrics.

Rolls up stats across every event in the security log - not one task
at a time (that's trace.py), but the full picture: how many actions
were allowed vs blocked, broken down by action type, risk level, work
type, and which resources get targeted most often.

Usage (from repo root):
    python -m gateway.metrics
"""

import json
from collections import Counter, defaultdict

from .events import LOG_FILE

RISK_LABELS = {1: "LOW", 2: "MEDIUM", 3: "HIGH", None: "UNKNOWN"}


def load_events():
    events = []
    try:
        with open(LOG_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    except FileNotFoundError:
        pass
    return events


def print_metrics():
    events = load_events()

    if not events:
        print("No events logged yet. Run some gateway calls first.")
        return

    total = len(events)
    allowed = sum(1 for e in events if e["decision"] == "allowed")
    blocked = total - allowed

    print("=== Security Metrics ===")
    print(f"Total events: {total}")
    print(f"Allowed: {allowed} ({allowed/total:.0%})")
    print(f"Blocked: {blocked} ({blocked/total:.0%})")

    # --- By action type ---
    print("\n--- By Action Type ---")
    by_action = defaultdict(lambda: {"allowed": 0, "blocked": 0})
    for e in events:
        by_action[e["action"]][e["decision"]] += 1
    for action, counts in sorted(by_action.items()):
        a, b = counts["allowed"], counts["blocked"]
        print(f"  {action:8} | allowed={a:3} | blocked={b:3} | total={a+b}")

    # --- By risk level ---
    print("\n--- By Risk Level ---")
    by_risk = defaultdict(lambda: {"allowed": 0, "blocked": 0})
    for e in events:
        by_risk[e["risk_level"]][e["decision"]] += 1
    for risk, counts in sorted(by_risk.items(), key=lambda kv: (kv[0] is None, kv[0])):
        label = RISK_LABELS.get(risk, str(risk))
        a, b = counts["allowed"], counts["blocked"]
        print(f"  {label:8} | allowed={a:3} | blocked={b:3} | total={a+b}")

    # --- By work type ---
    print("\n--- By Work Type ---")
    by_work = defaultdict(lambda: {"allowed": 0, "blocked": 0})
    for e in events:
        by_work[e["work_type"]][e["decision"]] += 1
    for wt, counts in sorted(by_work.items()):
        a, b = counts["allowed"], counts["blocked"]
        rate = b / (a + b) if (a + b) else 0
        print(f"  {wt:12} | allowed={a:3} | blocked={b:3} | block_rate={rate:.0%}")

    # --- Most frequently blocked resources ---
    print("\n--- Most Frequently Blocked Resources ---")
    blocked_resources = Counter(
        e["resource"] for e in events if e["decision"] == "blocked"
    )
    if blocked_resources:
        for resource, count in blocked_resources.most_common(10):
            print(f"  {count:3}x  {resource!r}")
    else:
        print("  (none blocked yet)")

    # --- Unique tasks seen ---
    unique_tasks = len(set(e["task_id"] for e in events))
    print(f"\nUnique tasks in log: {unique_tasks}")


if __name__ == "__main__":
    print_metrics()
