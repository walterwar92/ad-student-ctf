# CipherVault — Solution & Patch

## The vulnerability: AES-CTR keystream reuse (many-time pad)

AES-CTR is a **stream cipher** mode. It generates a keystream
`KS = AES_CTR(KEY, NONCE)` and produces ciphertext by XOR:

```
C = P XOR KS
```

The keystream depends only on `(KEY, NONCE)` and the counter position — it does
**not** depend on the plaintext. In `app.py` both the key and the nonce are
chosen once at process startup and then reused for *every* `/api/store` call:

```python
KEY = secrets.token_bytes(16)
NONCE = b"\x00" * 8

def _encrypt(pt):
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)   # same KEY + same NONCE every time
    return cipher.encrypt(pt)
```

So every item is XORed against the **identical** keystream. This is the classic
*two-time / many-time pad* mistake. Two ciphertexts share:

```
C1 = P1 XOR KS
C2 = P2 XOR KS
```

If an attacker knows one plaintext `P1`, they recover the keystream directly:

```
KS = P1 XOR C1
```

and then decrypt everything else: `P2 = C2 XOR KS`.

The second half of the bug is that `GET /api/item/<id>` **publicly exposes the
raw ciphertext** of every item (and `GET /api/items` enumerates all ids). The
attacker therefore has free access to both a chosen-plaintext oracle (store
their own secret, read its ciphertext) and the target ciphertext (the flag's
item), with no token required.

The token-gated `/api/reveal` path is *not* the bug — it is a correct,
authenticated decrypt and must stay as-is.

## Exploit recap

1. `POST /api/store` a known plaintext `P = "A"*256` → get an id.
2. `GET /api/item/<id>` → ciphertext `C`.
3. `KS = P XOR C` (recovered keystream, 256 bytes long — covers any 32-char flag).
4. `GET /api/item/<flag_id>` → `C_flag`.
5. `flag = C_flag XOR KS`.

Pure XOR, no key needed. See `sploit.py`.

## The fix

Use a **fresh random nonce for every encryption** and store it alongside the
ciphertext so decryption can reproduce the right keystream. Distinct nonces ⇒
distinct keystreams ⇒ recovering one keystream tells you nothing about another
item. (Defence in depth: you can also stop publishing raw ciphertext from
`/api/item`, but a per-item random nonce alone already kills the attack.)

### Patch — `store()`

Vulnerable:
```python
def _encrypt(pt):
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    return cipher.encrypt(pt)

# ...in store():
    ct = _encrypt(secret.encode("utf-8"))
    with _lock:
        _store[item_id] = {"owner": owner, "ct": ct, "token": token}
```

Fixed:
```python
# ...in store():
    nonce = secrets.token_bytes(8)                       # fresh nonce per item
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
    ct = cipher.encrypt(secret.encode("utf-8"))
    with _lock:
        _store[item_id] = {"owner": owner, "ct": ct, "nonce": nonce, "token": token}
```

### Patch — `reveal()`

Vulnerable:
```python
def _decrypt(ct):
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    return cipher.decrypt(ct)

# ...in reveal():
        pt = _decrypt(it["ct"])
```

Fixed:
```python
# ...in reveal():
        cipher = AES.new(KEY, AES.MODE_CTR, nonce=it["nonce"])
        pt = cipher.decrypt(it["ct"])
```

Delete the module-level `NONCE = b"\x00" * 8` and the fixed-nonce
`_encrypt`/`_decrypt` helpers. The exposed `ciphertext`/`length` still reflect
only the encrypted bytes, so the checker stays green; but because each item now
has its own keystream, the many-time-pad recovery produces garbage.

### One-line summary

- Vulnerable: `NONCE = b"\x00" * 8` reused for every `AES.new(KEY, AES.MODE_CTR, nonce=NONCE)`.
- Fixed: `nonce = secrets.token_bytes(8)` generated per store and saved with the ciphertext.
