# Depot - Solution

## Vulnerability: path traversal in `GET` (CWE-22)

Depot stores each user's values as files: `BASE/<user>/<key>`, where
`BASE = data/depot`. The flag for a given team lives in that team's account as
`BASE/<user>/<key>`, and the flag id that attackers receive is exactly
`<user>/<key>`.

`PUT` sanitizes the key before building the path (via `safe_name`, which rejects
`/`, `\`, `..`, and leading `.`), so an attacker cannot *write* files outside
their own directory. But `GET` builds the path with **no** validation of the
key:

```python
def get(token, key):
    with LOCK:
        user = TOKENS.get(token)
    if user is None:
        return "ERR badtoken"
    path = os.path.join(BASE, user, key)          # key is attacker-controlled, unchecked
    try:
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
    except OSError:
        return "ERR notfound"
    return "OK " + value
```

Because the key is interpolated straight into the path, a key that contains
`..` escapes the caller's directory. From `BASE/<attacker>/`, the component
`../<victim>/<victimkey>` resolves to `BASE/<victim>/<victimkey>` - the victim's
flag file. The attacker only needs a valid token (any freshly registered
account) and the public flag id.

## Exploitation

```
REGISTER attacker s3cret        -> OK <token>
GET <token> ../<victim>/<key>   -> OK <flag>
```

`sploit.py` automates this: register a random attacker account, split the
`flag_id` on the first `/`, and request `../<victim>/<key>`.

## The fix

Validate the key in `GET` exactly as `PUT` already does, so traversal sequences
and path separators are rejected before the path is built. The service already
has a `safe_name` helper - reuse it.

### Vulnerable line

```python
def get(token, key):
    with LOCK:
        user = TOKENS.get(token)
    if user is None:
        return "ERR badtoken"
    path = os.path.join(BASE, user, key)
    ...
```

### Fixed version

```python
def get(token, key):
    with LOCK:
        user = TOKENS.get(token)
    if user is None:
        return "ERR badtoken"
    if not safe_name(key):            # <-- added: reject "/", "\", "..", leading "."
        return "ERR notfound"         # <-- added
    path = os.path.join(BASE, user, key)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
    except OSError:
        return "ERR notfound"
    return "OK " + value
```

With the key validated, `../<victim>/<key>` is rejected (`ERR notfound`), while
normal single-component keys used by legitimate traffic still work, so the
checker stays green.

### Alternative hardening

Any of these also closes the hole:

- `key = os.path.basename(key)` to force a single component, or
- resolve the final path and confirm it stays inside the user's directory:

```python
base_dir = os.path.realpath(os.path.join(BASE, user))
path = os.path.realpath(os.path.join(base_dir, key))
if os.path.commonpath([base_dir, path]) != base_dir:
    return "ERR notfound"
```

Rejecting the key up front (the `safe_name` approach) is the smallest, clearest
patch and matches how `PUT` is already written.
