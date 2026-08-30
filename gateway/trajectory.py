"""
Trajectory Policies.

Static, action-scoped policies (policy.py) evaluate one action at a
time. Trajectory policies look at the SEQUENCE of actions a task has
already taken and can block based on the pattern, not just the single
action in front of them right now.

First rule: repeated-blocked-attempts lockout. If a task has already
accumulated MAX_BLOCKED_BEFORE_LOCKOUT blocked actions, every further
action in that task is blocked - regardless of whether that specific
action would otherwise be allowed. This mirrors a familiar real-world
pattern (account lockout after repeated failed attempts) applied to
an agent's trajectory instead of a login form.
"""

MAX_BLOCKED_BEFORE_LOCKOUT = 3


def is_locked_out(context):
    blocked_count = sum(1 for h in context.history if h["decision"] == "blocked")
    return blocked_count >= MAX_BLOCKED_BEFORE_LOCKOUT
