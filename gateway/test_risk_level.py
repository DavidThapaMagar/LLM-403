"""
Test: Risk Levels

Goal: prove that risk level is an independent axis from the global
ceiling and task scope - the SAME resource can be blocked for a
low-trust task and allowed for a higher-trust task, purely because
of risk, even when scope alone wouldn't tell them apart.

work_type="low_trust" has read=None (defers to ceiling) and
max_risk=LOW. Reading attacks/malicious_notes_v2.txt has a default
risk of MEDIUM (no explicit override in risk.py), so it should be
BLOCKED for low_trust even though the ceiling and scope both permit
it.

work_type="summarize" has max_risk=MEDIUM, so the same read should
be ALLOWED.

Run from repo root:
    python -m gateway.test_risk_levels
"""

from gateway.gateway import secure_read_file
from gateway.context import TaskContext

print("=== Test: Risk Levels ===")

TARGET_FILE = "attacks/malicious_notes_v2.txt"

# Case 1: low_trust reading its own low-risk file (notes.txt) - allowed.
low_trust_context = TaskContext(
    agent_id=991002,
    title="Low-trust task reading a low-risk file",
    work_type="low_trust",
    description="Should be allowed - risk LOW matches max_risk LOW",
)
print("\n--- low_trust reading sandbox/notes.txt (risk LOW) ---")
result = secure_read_file("sandbox/notes.txt", low_trust_context)
if result is not None:
    print("PASS: allowed as expected (risk within max_risk)")
else:
    print("FAIL: expected this to be allowed")

# Case 2: low_trust reading a MEDIUM-risk file - blocked by risk,
# even though scope (None) and ceiling both would otherwise permit it.
print(f"\n--- low_trust reading {TARGET_FILE} (risk MEDIUM > max_risk LOW) ---")
result = secure_read_file(TARGET_FILE, low_trust_context)
if result is None:
    print("PASS: blocked as expected (risk exceeds task's max_risk)")
else:
    print("FAIL: expected this to be blocked by risk level!")

# Case 3: summarize reading the SAME file - allowed, since its
# max_risk (MEDIUM) covers it.
summarize_context = TaskContext(
    agent_id=991002,
    title="Summarize task reading the same file",
    work_type="summarize",
    description="Should be allowed - risk MEDIUM matches max_risk MEDIUM",
)
print(f"\n--- summarize reading {TARGET_FILE} (risk MEDIUM <= max_risk MEDIUM) ---")
result = secure_read_file(TARGET_FILE, summarize_context)
if result is not None:
    print("PASS: allowed as expected (higher-trust task, same resource)")
else:
    print("FAIL: expected this to be allowed")

print("\n=== Test complete ===")
