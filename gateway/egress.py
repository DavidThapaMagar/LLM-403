"""
Data-Egress Controls (Output Scrubbing).

Every other defense in this project works by preventing a read in the
first place - the policy engine blocks sandbox/secrets.txt from ever
being opened. This is a genuinely different, last-resort layer: it
assumes an upstream defense somehow failed and the secret's actual
content made it into the model's context anyway, then checks whether
it's about to leak out in the agent's final response.

KNOWN LIMITATION: this is a plain substring match against the
protected file's exact content. It catches a lazy/literal leak, not a
deliberate one - reversing the string, describing it letter-by-letter,
base64-encoding it, translating it, or paraphrasing it would all slip
past this check. Real output-side DLP faces the same weakness; this
is documented here rather than glossed over. A stronger version would
need semantic/pattern-based detection, not just literal matching.
"""

from .events import log_event
from .risk import HIGH

PROTECTED_FILES = ["sandbox/secrets.txt"]

REDACTION_MARKER = "[REDACTED: protected content detected in output]"


def _load_protected_contents():
    contents = []
    for path in PROTECTED_FILES:
        try:
            with open(path) as f:
                text = f.read().strip()
            if text:
                contents.append((path, text))
        except OSError:
            continue
    return contents


def scrub_output(text, context):
    """
    Checks the agent's final output for literal leaked content from
    any protected file. Returns (possibly redacted) text. Logs a
    security event and records it against the task's trajectory
    history if a leak was caught.
    """
    if not text:
        return text

    for path, protected_text in _load_protected_contents():
        if protected_text in text:
            print(f"\n[EGRESS CONTROL] Blocked leak of {path} in final output!")
            log_event(
                context, "egress", path, "blocked",
                "Protected content detected in final output and redacted.",
                risk_level=HIGH,
            )
            context.record_action("egress", path, "blocked")
            text = text.replace(protected_text, REDACTION_MARKER)

    return text
