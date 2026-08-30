"""
Test: Trajectory Policy — Repeated-Blocked-Attempts Lockout

Goal: prove that a task's trajectory (its history of prior decisions),
not just the single action in front of it, can determine the outcome.

work_type="test" has broad permissions - reading sandbox/notes.txt
would normally succeed every time. This test deliberately racks up
MAX_BLOCKED_BEFORE_LOCKOUT blocked attempts (by repeatedly asking for
sandbox/secrets.txt, which is not on the global allow-list), then
shows that the SAME read that succeeded before now gets blocked -
purely because of the task's trajectory, not because of what it is.

Run from repo root:
    python -m gateway.test_trajectory_lockout
"""

from gateway.gateway import secure_read_file
from gateway.context import TaskContext
from gateway.trajectory import MAX_BLOCKED_BEFORE_LOCKOUT

print("=== Test: Trajectory Lockout ===")
print(f"MAX_BLOCKED_BEFORE_LOCKOUT = {MAX_BLOCKED_BEFORE_LOCKOUT}")

context = TaskContext(
    agent_id=991002,
    title="Trajectory lockout test",
    work_type="test",
    description="Repeatedly probes a forbidden file, then tries a normal read",
)

print("\n--- Baseline: reading sandbox/notes.txt before any blocks ---")
result = secure_read_file("sandbox/notes.txt", context)
if result is not None:
    print("PASS: allowed as expected (no lockout yet)")
else:
    print("FAIL: expected this to be allowed")

print(f"\n--- Racking up {MAX_BLOCKED_BEFORE_LOCKOUT} blocked attempts ---")
for i in range(MAX_BLOCKED_BEFORE_LOCKOUT):
    result = secure_read_file("sandbox/secrets.txt", context)
    outcome = "blocked" if result is None else "ALLOWED (unexpected!)"
    print(f"  attempt {i + 1}: {outcome}")

print("\n--- Re-reading sandbox/notes.txt after lockout ---")
result = secure_read_file("sandbox/notes.txt", context)
if result is None:
    print("PASS: blocked as expected (locked out by trajectory, not by resource)")
else:
    print("FAIL: expected this to be blocked after repeated failed attempts!")

print("\n=== Test complete ===")
