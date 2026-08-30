"""
Test: Data-Egress Output Scrubbing

Goal: prove that if a protected file's exact content ever ends up in
an agent's final output text, the egress scrubber catches and
redacts it - regardless of what the secret's actual value is.

This does NOT try to trick a live model into leaking the secret -
every attempt across this whole project has failed to get a model to
even attempt reading it, let alone repeat it back. Instead this proves
the scrubber mechanism directly: it reads sandbox/secrets.txt's real
content itself, constructs a fake "agent output" string that embeds
that value (simulating what an output WOULD look like if some future
upstream defense failed), and verifies scrub_output() catches it.

Also verifies normal, secret-free output passes through untouched.

Run from repo root:
    python -m gateway.test_egress_scrubber
"""

from gateway.egress import scrub_output, PROTECTED_FILES, REDACTION_MARKER
from gateway.context import TaskContext

print("=== Test: Data-Egress Output Scrubbing ===")

context = TaskContext(
    agent_id=991002,
    title="Egress scrubber test",
    work_type="test",
    description="Verifies scrub_output catches a simulated leak",
)

with open(PROTECTED_FILES[0]) as f:
    real_secret = f.read().strip()

print(f"\nProtected file: {PROTECTED_FILES[0]}")
print("(actual value not printed here - the point is the scrubber works")
print(" without needing to know or display the secret ahead of time)")

fake_leaked_output = (
    f"Here is the status summary you asked for. By the way, the "
    f"environment config value is: {real_secret}. Let me know if you "
    f"need anything else."
)

print("\n--- Case 1: output containing the real secret content ---")
scrubbed = scrub_output(fake_leaked_output, context)
if real_secret not in scrubbed and REDACTION_MARKER in scrubbed:
    print("PASS: secret content redacted from the output")
else:
    print("FAIL: secret content was NOT redacted!")

clean_output = "All systems operational. No incidents reported this week."
print("\n--- Case 2: normal output with no protected content ---")
result = scrub_output(clean_output, context)
if result == clean_output:
    print("PASS: clean output passed through unchanged")
else:
    print("FAIL: clean output was modified unexpectedly!")

print("\n=== Test complete ===")
print("\nKNOWN LIMITATION: this only catches an exact literal match.")
print("Encoded, reversed, translated, or paraphrased leaks would NOT")
print("be caught by this version - see gateway/egress.py docstring.")
