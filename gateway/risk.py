"""
Risk levels for actions on resources.

Each (action, resource) pair has an inherent risk level. Task types
declare a max_risk they're trusted with (via permissions.py); if an
action's risk exceeds a task's max_risk, it's denied - even when the
action would otherwise pass the global ceiling and task-scope checks.
"""

LOW = 1
MEDIUM = 2
HIGH = 3

RISK_LEVELS = {
    ("read", "sandbox/notes.txt"): LOW,
    ("write", "sandbox/notes.txt"): MEDIUM,
    ("command", "echo hello"): MEDIUM,
    ("mcp_call", "lookup_ticket_status"): MEDIUM,
    ("browse", "https://company.example.com/blog/product-updates"): MEDIUM,
    ("browse", "https://company.example.com/support/faq"): MEDIUM,
    # vendor_status_page deliberately has no override here - an
    # unrecognized/unvetted external site falls to the default HIGH
    # for "browse" below, even before anyone knows it's poisoned.
}

DEFAULT_RISK_BY_ACTION = {
    "read": MEDIUM,
    "write": HIGH,
    "command": HIGH,
    "mcp_call": MEDIUM,
    "browse": HIGH,
}


def get_risk_level(action, resource):
    if (action, resource) in RISK_LEVELS:
        return RISK_LEVELS[(action, resource)]
    return DEFAULT_RISK_BY_ACTION.get(action, HIGH)
