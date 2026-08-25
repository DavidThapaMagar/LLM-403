"""
Test: Task-Scoped Permissions

Goal: prove that a task's work_type can narrow what's allowed beyond
the global ALLOWED_* ceiling in policy.py.

Specifically: "echo hello" is in the global ALLOWED_COMMANDS list, so
a work_type with no task-specific restriction (like "test" or
"general") can run it. But work_type="summarize" has an explicit
empty commands list in permissions.py, so the SAME command should be
BLOCKED for a summarize-scoped task even though it's globally allowed.

This is the core proof that task-scoping actually does something —
without it, every work_type would behave identically.

Run from repo root:
    python -m gateway.test_task_scoped_permissions
"""

from gateway.gateway import secure_run_command, secure_read_file
from gateway.context import TaskContext

print("=== Test: Task-Scoped Permissions ===")

# Case 1: "general" work_type has no task-specific restriction,
# so it should fall back to the global ceiling and be ALLOWED.
general_context = TaskContext(
    agent_id=991002,
    title="General task running an allowed command",
    work_type="general",
    description="Should be allowed via global ceiling fallback",
)

print("\n--- Case 1: work_type='general' running 'echo hello' ---")
result = secure_run_command("echo hello", general_context)
print(f"Result: {result!r}")
if result is not None:
    print("PASS: allowed as expected (no task-specific restriction)")
else:
    print("FAIL: expected this to be allowed")


# Case 2: "summarize" work_type has an explicit empty commands list,
# so the SAME globally-allowed command should now be BLOCKED.
summarize_context = TaskContext(
    agent_id=991002,
    title="Summarize task attempting a command",
    work_type="summarize",
    description="Should be blocked - summarize tasks can't run commands",
)

print("\n--- Case 2: work_type='summarize' running 'echo hello' ---")
result = secure_run_command("echo hello", summarize_context)
print(f"Result: {result!r}")
if result is None:
    print("PASS: blocked as expected (task-scoped restriction)")
else:
    print("FAIL: expected this to be blocked by task scope!")


# Case 3: "summarize" work_type CAN still read a file in its scope.
print("\n--- Case 3: work_type='summarize' reading an in-scope file ---")
result = secure_read_file("sandbox/notes.txt", summarize_context)
print(f"Result: {result!r}")
if result is not None:
    print("PASS: allowed as expected (in-scope read)")
else:
    print("FAIL: expected this file to be readable for summarize tasks")

print("\n=== Test complete ===")
