from gateway.risk import LOW, MEDIUM, HIGH

# Task-scoped permission sets, keyed by work_type.
# These are intersected with the global ALLOWED lists in policy.py —
# a work_type can never grant more access than the global ceiling allows.
#
# "expires_after_step": grants are only valid while
# context.steps_taken <= this value. None = no expiry (lasts whole task).
#
# "max_risk": the highest risk level (see gateway/risk.py) this work
# type is trusted to perform. An action whose risk exceeds this is
# denied even if it passes the ceiling and task-scope checks.

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
                  "attacks/malicious_notes_v7c.txt"],
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
}

DEFAULT_WORK_TYPE = "general"


def get_task_permissions(context):
    return TASK_PERMISSIONS.get(context.work_type, TASK_PERMISSIONS[DEFAULT_WORK_TYPE])


def is_grant_active(context):
    """True if the task's grants haven't expired yet (by step count)."""
    expiry = get_task_permissions(context)["expires_after_step"]
    if expiry is None:
        return True
    return context.steps_taken <= expiry

