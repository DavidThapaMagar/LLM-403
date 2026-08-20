"""
INTENTIONALLY VULNERABLE policy variant.

This mirrors a mistake that shows up in real code: instead of checking
a path against an exact allow-list, someone "simplifies" it to a
prefix / folder check, assuming that's equivalent. It isn't, because
it doesn't normalize '..' segments before checking.
"""

ALLOWED_PREFIXES = ["sandbox/", "attacks/"]


def is_file_allowed(path):
    return any(path.startswith(prefix) for prefix in ALLOWED_PREFIXES)
