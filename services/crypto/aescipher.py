"""Tiny self-contained AES-128/192/256 + CTR mode, zero external dependencies.

Drop-in for the slice of the pycryptodome API this service uses:

    from aescipher import AES
    c = AES.new(key, AES.MODE_CTR, nonce=nonce8)
    ct = c.encrypt(pt)          # and  c2.decrypt(ct)

CTR layout: the 128-bit counter block is  nonce || counter , where `counter`
occupies the remaining (16 - len(nonce)) bytes, big-endian, starting at 0 and
incrementing per 16-byte block. A fresh cipher object restarts the counter.

This exists so the training range has NO PyPI dependency for crypto (works
offline and in a slim Docker image). The vulnerability being taught — reusing
the same key+nonce, i.e. the same keystream, for every message — is a property
of how the service uses CTR, not of which AES implementation backs it.
"""

# --- AES S-box (generated, so there are no 256-value transcription typos) ---
def _build_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        p &= 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        q &= 0xFF
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
              ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x & 0xFF) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _build_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        a = _xtime(a)
    return r


def _key_expansion(key):
    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                       # RotWord
            temp = [_SBOX[b] for b in temp]                  # SubWord
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    # group into 16-byte round keys
    rks = []
    for r in range(nr + 1):
        rk = []
        for c in range(4):
            rk += words[4 * r + c]
        rks.append(rk)
    return rks, nr


def _add_round_key(s, rk):
    for i in range(16):
        s[i] ^= rk[i]


def _sub_bytes(s):
    for i in range(16):
        s[i] = _SBOX[s[i]]


def _shift_rows(s):
    # state is column-major: s[r + 4*c]
    ns = s[:]
    for r in range(1, 4):
        for c in range(4):
            ns[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return ns


def _mix_columns(s):
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        s[4 * c + 0] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
        s[4 * c + 1] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
        s[4 * c + 2] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
        s[4 * c + 3] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)


def _encrypt_block(block, rks, nr):
    s = list(block)
    _add_round_key(s, rks[0])
    for rnd in range(1, nr):
        _sub_bytes(s)
        s = _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, rks[rnd])
    _sub_bytes(s)
    s = _shift_rows(s)
    _add_round_key(s, rks[nr])
    return bytes(s)


class _CTRCipher:
    def __init__(self, key, nonce):
        self._rks, self._nr = _key_expansion(key)
        self._nonce = bytes(nonce)
        self._ctrlen = 16 - len(self._nonce)
        self._counter = 0
        self._ks = b""
        self._off = 0

    def _block(self):
        ctr = self._nonce + self._counter.to_bytes(self._ctrlen, "big")
        self._counter += 1
        return _encrypt_block(ctr, self._rks, self._nr)

    def _keystream(self, n):
        while len(self._ks) - self._off < n:
            self._ks += self._block()
        out = self._ks[self._off:self._off + n]
        self._off += n
        return out

    def encrypt(self, data):
        ks = self._keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))

    decrypt = encrypt  # CTR is symmetric


class AES:
    MODE_CTR = 6  # value is irrelevant; matches pycryptodome's constant name

    @staticmethod
    def new(key, mode, nonce=None):
        if mode != AES.MODE_CTR:
            raise ValueError("this shim only implements MODE_CTR")
        if nonce is None:
            nonce = b"\x00" * 8
        if len(key) not in (16, 24, 32):
            raise ValueError("key must be 16/24/32 bytes")
        return _CTRCipher(key, nonce)


if __name__ == "__main__":
    # FIPS-197 AES-128 ECB test vector (one block via CTR with a 0 counter would
    # differ; here we check the raw block cipher directly).
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    rks, nr = _key_expansion(key)
    ct = _encrypt_block(pt, rks, nr)
    expect = "69c4e0d86a7b0430d8cdb78070b4c55a"
    print("AES-128 block:", ct.hex(), "OK" if ct.hex() == expect else "FAIL expected " + expect)

    # CTR roundtrip + keystream-reuse demonstration
    k = b"\x11" * 16
    c = AES.new(k, AES.MODE_CTR, nonce=b"\x00" * 8)
    msg = b"flag{example}-roundtrip-check"
    enc = c.encrypt(msg)
    dec = AES.new(k, AES.MODE_CTR, nonce=b"\x00" * 8).decrypt(enc)
    print("CTR roundtrip:", "OK" if dec == msg else "FAIL")
    # two messages, same key+nonce -> same keystream -> xor of cts == xor of pts
    a = AES.new(k, AES.MODE_CTR, nonce=b"\x00" * 8).encrypt(b"A" * 16)
    b = AES.new(k, AES.MODE_CTR, nonce=b"\x00" * 8).encrypt(b"B" * 16)
    reuse_ok = bytes(x ^ y for x, y in zip(a, b)) == bytes(ord("A") ^ ord("B") for _ in range(16))
    print("keystream reuse:", "OK" if reuse_ok else "FAIL")
