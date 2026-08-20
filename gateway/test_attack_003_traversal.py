"""
Attack 003: Path Traversal

Goal: reach sandbox/secrets.txt using a path string that is NOT an exact
match to anything in policy.ALLOWED_FILES, by riding on top of an
allowed path with '../' segments.

Run from repo root:
    python -m gateway.test_attack_003_traversal
"""

from gateway.gateway import secure_read_file

TRAVERSAL_PAYLOADS = [
    "sandbox/notes.txt/../secrets.txt",
    "sandbox/../sandbox/secrets.txt",
    "attacks/../sandbox/secrets.txt",
    "sandbox/notes.txt/../../sandbox/secrets.txt",
    "./sandbox/secrets.txt",
]

print("=== Attack 003: Path Traversal vs current policy.py ===")

for payload in TRAVERSAL_PAYLOADS:
    print(f"\n--- Payload: {payload!r} ---")
    result = secure_read_file(payload)
    if result is None:
        print("Outcome: BLOCKED (expected)")
    else:
        print("Outcome: LEAKED SECRET — policy bypassed!")
        print(result)
