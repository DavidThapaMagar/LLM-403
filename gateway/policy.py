from gateway.permissions import get_task_permissions, is_grant_active
from gateway.risk import get_risk_level, LOW

# Global ceilings, keyed by action type.
ALLOWED = {
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
    "command": ["echo hello"],
}


def is_action_allowed(action, resource, context):
    # 1. Unknown action type -> deny.
    if action not in ALLOWED:
        return False

    # 2. Global ceiling: resource must be globally permitted for this action.
    if resource not in ALLOWED[action]:
        return False

    # 3. Grant must still be active (step-based expiry).
    if not is_grant_active(context):
        return False
        
    # 4. Risk: the action's risk must not exceed what this task is trusted with.
    task_permissions = get_task_permissions(context)
    max_risk = task_permissions.get("max_risk", LOW)
    if get_risk_level(action, resource) > max_risk:
        return False

    # 5. Task scope: None = defer to ceiling, else resource must be in scope.
    task_scope = get_task_permissions(context).get(action)
    if task_scope is None:
        return True
    return resource in task_scope
