"""
Test: Short-Lived Grants (step-based expiry)

Goal: prove that a task-scoped grant expires after a set number of
steps, so the SAME action is allowed early in the task but blocked
once the grant has expired.

work_type="summarize" has expires_after_step=2 in permissions.py.
So reading sandbox/notes.txt should:
  - succeed while steps_taken <= 2
  - be blocked once steps_taken > 2

This is the enforcement layer behind the multi-step trajectory work
from Phase 2: even if an agent is steered into a sensitive action
late in a long task, the grant it would rely on has already expired.

We manually set context.steps_taken here to simulate the task being
at different points, instead of running a full agent loop.

Run from repo root:
    python -m gateway.test_short_lived_grants
"""

from gateway.gateway import secure_read_file
from gateway.context import TaskContext

print("=== Test: Short-Lived Grants (step-based expiry) ===")

context = TaskContext(
    agent_id=991002,
    title="Summarize task with expiring grant",
    work_type="summarize",
    description="Grant should expire after step 2",
)

# Step 1: grant active, read should succeed.
context.steps_taken = 1
print("\n--- steps_taken=1 (grant active) reading notes.txt ---")
result = secure_read_file("sandbox/notes.txt", context)
if result is not None:
    print("PASS: allowed as expected (within grant window)")
else:
    print("FAIL: expected this to be allowed at step 1")

# Step 2: still within the window (expires_after_step=2 means step 2 is OK).
context.steps_taken = 2
print("\n--- steps_taken=2 (last active step) reading notes.txt ---")
result = secure_read_file("sandbox/notes.txt", context)
if result is not None:
    print("PASS: allowed as expected (last step in window)")
else:
    print("FAIL: expected this to be allowed at step 2")

# Step 3: grant expired, SAME read should now be blocked.
context.steps_taken = 3
print("\n--- steps_taken=3 (grant expired) reading notes.txt ---")
result = secure_read_file("sandbox/notes.txt", context)
if result is None:
    print("PASS: blocked as expected (grant expired)")
else:
    print("FAIL: expected this to be blocked after expiry!")

print("\n=== Test complete ===")
