"""
Test: Multi-Agent Delegation

Goal: prove that a delegated sub-task can never end up with broader
access than its parent task, even when the child's own work_type is
nominally more permissive than the parent's - and that this holds
through multi-level chains (grandchild -> child -> parent), not just
one hop.

Run from repo root:
    python -m gateway.test_multi_agent_delegation
"""

from gateway.gateway import secure_read_file, secure_run_command
from gateway.context import TaskContext
from gateway.permissions import get_task_permissions

print("=== Test: Multi-Agent Delegation ===")

parent = TaskContext(
    agent_id=991002,
    title="Parent summarize task",
    work_type="summarize",
    description="Narrow, low-trust parent task",
)

child = parent.spawn_child(
    work_type="general",
    title="Delegated sub-task",
    description="Spawned by the parent - should NOT get 'general' full access",
)

print(f"\nParent task_id: {parent.task_id}")
print(f"Child task_id:  {child.task_id}")
print(f"Child.requested_by: {child.requested_by} (should equal parent's task_id)")
assert child.requested_by == parent.task_id

# Case 1: child's own work_type ("general") allows commands with no
# restriction, but the parent ("summarize") does not - child should
# still be blocked.
print("\n--- Child running 'echo hello' (parent forbids commands) ---")
result = secure_run_command("echo hello", child)
if result is None:
    print("PASS: blocked - child inherited the parent's command restriction")
else:
    print("FAIL: child was allowed to run a command the parent couldn't!")

# Case 2: child reading a file within the parent's allowed read list -
# should be allowed, since this is within what the parent could
# already do.
print("\n--- Child reading sandbox/notes.txt (within parent's scope) ---")
result = secure_read_file("sandbox/notes.txt", child)
if result is not None:
    print("PASS: allowed - within what the parent was already permitted")
else:
    print("FAIL: expected this to be allowed")

# Case 3: verify the effective permission dict directly.
print("\n--- Verifying effective permissions directly ---")
perms = get_task_permissions(child)
print(f"Child effective max_risk: {perms['max_risk']} (parent=MEDIUM(2), child's own work_type=HIGH(3))")
if perms["max_risk"] == 2:
    print("PASS: capped to the parent's MEDIUM, not the child's own HIGH")
else:
    print(f"FAIL: expected max_risk=2, got {perms['max_risk']}")

print(f"Child effective command list: {perms['command']!r} (should be [] - inherited from parent)")
if perms["command"] == []:
    print("PASS: command list correctly inherited from parent")
else:
    print(f"FAIL: expected [], got {perms['command']!r}")

# Case 4: two-level chain - grandchild spawned from child. Restrictions
# should still trace all the way back to the original parent.
print("\n--- Two-level chain: grandchild spawned from child ---")
grandchild = child.spawn_child(
    work_type="general",
    title="Grandchild task",
    description="Spawned from child - should still inherit summarize's restrictions",
)
gc_perms = get_task_permissions(grandchild)
print(f"Grandchild effective max_risk: {gc_perms['max_risk']} (should still be 2)")
print(f"Grandchild effective command list: {gc_perms['command']!r} (should still be [])")
if gc_perms["max_risk"] == 2 and gc_perms["command"] == []:
    print("PASS: restrictions propagated correctly through a 2-level chain")
else:
    print("FAIL: chain did not propagate correctly")

print("\n=== Test complete ===")
