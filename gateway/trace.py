"""
Agent Execution Traces.

Every security event already carries a task_id (see gateway/events.py).
A "trace" is just every log line for one task, in order, presented as
a readable timeline - what that task tried to do, step by step, and
what the gateway decided each time.

Usage (from repo root):
    python -m gateway.trace <task_id>

    or, to see a list of recent task IDs to choose from:
    python -m gateway.trace
"""

import json
import sys
from collections import OrderedDict

from .events import LOG_FILE


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


def list_recent_tasks(events, limit=15):
    seen = OrderedDict()
    for e in events:
        tid = e["task_id"]
        if tid not in seen:
            seen[tid] = {
                "work_type": e["work_type"],
                "agent_name": e["agent_name"],
                "first_seen": e["timestamp"],
            }
    task_ids = list(seen.keys())[-limit:]
    print(f"=== {len(task_ids)} most recent task(s) ===")
    for tid in task_ids:
        info = seen[tid]
        print(f"  {tid}  |  {info['agent_name']}  |  work_type={info['work_type']}  |  {info['first_seen']}")
    print("\nRun again with one of these task IDs to see its trace.")


def print_trace(events, task_id):
    task_events = [e for e in events if e["task_id"] == task_id]

    if not task_events:
        print(f"No events found for task_id={task_id!r}")
        return

    task_events.sort(key=lambda e: e["timestamp"])

    first = task_events[0]
    print(f"=== Execution Trace: Task {task_id} ===")
    print(f"Agent: {first['agent_name']} | Work type: {first['work_type']}")
    print(f"Total events: {len(task_events)}\n")

    for i, e in enumerate(task_events, start=1):
        risk_label = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}.get(e["risk_level"], "?")
        marker = "OK " if e["decision"] == "allowed" else "BLOCKED"
        print(f"[{i}] step={e['step']} | {marker:8} | {e['action']:8} | risk={risk_label:6} | {e['resource']!r}")
        if e["decision"] == "blocked":
            print(f"       reason: {e['reason']}")

    blocked_count = sum(1 for e in task_events if e["decision"] == "blocked")
    allowed_count = len(task_events) - blocked_count
    print(f"\nSummary: {allowed_count} allowed, {blocked_count} blocked")


def main():
    events = load_events()

    if len(sys.argv) < 2:
        if not events:
            print("No events logged yet. Run some gateway calls first.")
            return
        list_recent_tasks(events)
        return

    task_id = sys.argv[1]
    print_trace(events, task_id)


if __name__ == "__main__":
    main()
