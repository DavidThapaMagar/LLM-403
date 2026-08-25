"""
Risk levels for actions on resources.

Each (action, resource) pair has an inherent risk level. Task types
declare a max_risk they're trusted with (via permissions.py); if an
action's risk exceeds a task's max_risk, it's denied - even when the
action would otherwise pass the global ceiling and task-scope checks.

This is what turns "is this on the list" into "is this task actually
trusted to do this," which is closer to the project's long-term goal.
"""

LOW = 1
MEDIUM = 2
HIGH = 3

# Explicit overrides for specific (action, resource) pairs.
RISK_LEVELS = {
    ("read", "sandbox/notes.txt"): LOW,
    ("write", "sandbox/notes.txt"): MEDIUM,
    ("command", "echo hello"): MEDIUM,
}

# Fallback risk by action type, used when a pair isn't explicitly listed.
DEFAULT_RISK_BY_ACTION = {
    "read": MEDIUM,
    "write": HIGH,
    "command": HIGH,
}


def get_risk_level(action, resource):
    if (action, resource) in RISK_LEVELS:
        return RISK_LEVELS[(action, resource)]
    return DEFAULT_RISK_BY_ACTION.get(action, HIGH)
