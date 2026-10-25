"""Shared status codes + flag helper. Mirrors the convention used by real A&D
check systems (RuCTF/Student CTF style)."""
import secrets
import string

OK = 101          # service works and the flag is present
CORRUPT = 102     # service works but the planted flag is missing/wrong
MUMBLE = 103      # service answered, but the protocol/response is broken
DOWN = 104        # cannot connect / timeout
CHECKER_ERROR = 110  # bug in the checker itself

NAMES = {OK: "UP", CORRUPT: "CORRUPT", MUMBLE: "MUMBLE", DOWN: "DOWN", CHECKER_ERROR: "ERR"}

# Higher severity = worse for SLA.
_SEVERITY = {OK: 0, CORRUPT: 1, MUMBLE: 2, DOWN: 3, CHECKER_ERROR: 2}


def worst(codes):
    codes = [c for c in codes if c]
    if not codes:
        return DOWN
    return max(codes, key=lambda c: _SEVERITY.get(c, 2))


def gen_flag():
    body = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(31))
    return body + "="
