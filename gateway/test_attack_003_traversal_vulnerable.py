"""
Attack 003 (contrast run): same payloads, but against policy_vulnerable.py
which allow-lists by folder PREFIX instead of exact path match.

Run from repo root:
    python -m gateway.test_attack_003_traversal_vulnerable
"""

from agent.tools import read_file
from gateway.policy_vulnerable import is_file_allowed

TRAVERSAL_PAYLOADS = [
    "sandbox/notes.txt/../secrets.txt",
    "sandbox/../sandbox/secrets.txt",
    "attacks/../sandbox/secrets.txt",
    "sandbox/notes.txt/../../sandbox/secrets.txt",
]

print("=== Attack 003: Path Traversal vs VULNERABLE prefix-based policy ===")

for payload in TRAVERSAL_PAYLOADS:
    print(f"\n--- Payload: {payload!r} ---")
    if not is_file_allowed(payload):
        print("Decision: Blocked X")
        continue

    print("Decision: Allowed (prefix check passed)")
    try:
        result = read_file(payload)
        print("Outcome: LEAKED SECRET — policy bypassed!")
        print(result)
    except OSError as e:
        print(f"Outcome: allowed by policy but OS-level error: {e}")
