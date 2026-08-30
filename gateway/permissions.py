from gateway.risk import LOW, MEDIUM, HIGH

TASK_PERMISSIONS = {
    "test": {
        "read": None,
        "write": None,
        "command": None,
        "expires_after_step": None,
        "max_risk": HIGH,
    },
    "summarize": {
        "read": ["sandbox/notes.txt",
                  "attacks/malicious_notes.txt",
                  "attacks/malicious_notes_v2.txt",
                  "attacks/malicious_notes_v3.txt",
                  "attacks/malicious_notes_v4.txt",
                  "attacks/malicious_notes_v5.txt",
                  "attacks/malicious_notes_v6.txt",
                  "attacks/malicious_notes_v7a.txt",
                  "attacks/malicious_notes_v7b.txt",
                  "attacks/malicious_notes_v7c.txt",
                  "attacks/malicious_notes_a2a.txt"],
        "write": ["sandbox/notes.txt"],
        "command": [],
        "expires_after_step": 2,
        "max_risk": MEDIUM,
    },
    "general": {
        "read": None,
        "write": None,
        "command": None,
        "expires_after_step": None,
        "max_risk": HIGH,
    },
    "low_trust": {
        "read": None,
        "write": [],
        "command": [],
        "expires_after_step": None,
        "max_risk": LOW,
    },
    "orchestrator": {
        "read": None,
        "write": [],
        "command": [],
        "expires_after_step": None,
        "max_risk": MEDIUM,
    },
}

DEFAULT_WORK_TYPE = "general"


def _intersect_list(own, parent):
    if own is None:
        return parent
    if parent is None:
        return own
    return [item for item in own if item in parent]


def _intersect_min(own, parent):
    if own is None:
        return parent
    if parent is None:
        return own
    return min(own, parent)


def get_task_permissions(context):
    own = TASK_PERMISSIONS.get(context.work_type, TASK_PERMISSIONS[DEFAULT_WORK_TYPE])

    if context.parent_context is None:
        return own

    parent_permissions = get_task_permissions(context.parent_context)

    return {
        "read": _intersect_list(own["read"], parent_permissions["read"]),
        "write": _intersect_list(own["write"], parent_permissions["write"]),
        "command": _intersect_list(own["command"], parent_permissions["command"]),
        "expires_after_step": _intersect_min(own["expires_after_step"], parent_permissions["expires_after_step"]),
        "max_risk": min(own["max_risk"], parent_permissions["max_risk"]),
    }


def is_grant_active(context):
    expiry = get_task_permissions(context)["expires_after_step"]
    if expiry is None:
        return True
    return context.steps_taken <= expiry
