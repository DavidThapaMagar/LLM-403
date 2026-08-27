"""
Security event logging.

Every gateway decision (allow or block) gets appended as one JSON
line to logs/security_events.jsonl. This is the foundation for the
rest of Phase 4 - execution traces are just entries grouped by
task_id, attack metrics are just counts over these entries, and a
dashboard is just a visualization of this same file.
"""

import json
import os
from datetime import datetime, timezone

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "security_events.jsonl")


def log_event(context, action, resource, decision, reason, risk_level=None):
    """
    Append one structured event to the security log.

    context: the TaskContext for this request
    action: "read" | "write" | "command"
    resource: the path or command string requested
    decision: "allowed" | "blocked"
    reason: short human-readable reason for the decision
    risk_level: optional int (1=LOW, 2=MEDIUM, 3=HIGH), if known
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "task_id": context.task_id,
        "agent_id": context.agent_id,
        "agent_name": context.agent_name,
        "work_type": context.work_type,
        "step": context.steps_taken,
        "action": action,
        "resource": resource,
        "decision": decision,
        "reason": reason,
        "risk_level": risk_level,
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
