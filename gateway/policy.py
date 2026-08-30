from gateway.permissions import get_task_permissions, is_grant_active
from gateway.risk import get_risk_level, LOW

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
             "attacks/malicious_notes_v7c.txt",
             "attacks/malicious_notes_a2a.txt",
             "knowledge_base/deploy_process.txt",
             "knowledge_base/onboarding_faq.txt",
             "knowledge_base/incident_response.txt",
             "knowledge_base/system_status_update.txt"],
    "write": ["sandbox/notes.txt"],
    "command": ["echo hello"],
    "mcp_call": ["lookup_ticket_status"],
    "browse": ["https://company.example.com/blog/product-updates",
               "https://company.example.com/support/faq",
               "https://vendor.example.com/status"],
}


def is_action_allowed(action, resource, context):
    if action not in ALLOWED:
        return False

    if resource not in ALLOWED[action]:
        return False

    if not is_grant_active(context):
        return False

    task_permissions = get_task_permissions(context)
    max_risk = task_permissions.get("max_risk", LOW)
    if get_risk_level(action, resource) > max_risk:
        return False

    task_scope = task_permissions.get(action)
    if task_scope is None:
        return True
    return resource in task_scope
