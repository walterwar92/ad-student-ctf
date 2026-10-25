# CipherVault — Hints

Work through these in order. Each is hidden behind a spoiler.

<details>
<summary>Hint 1 — Where is the attack surface?</summary>

You never get the `token` for someone else's item, so `/api/reveal` is closed
to you. But look at what is handed out for free. Which endpoints return data
without any secret at all?
</details>

<details>
<summary>Hint 2 — What exactly is exposed?</summary>

`GET /api/item/<id>` returns the raw `ciphertext` of every item, including
items you do not own. The flag lives inside one of those ciphertexts. So the
question becomes: can you turn ciphertext into plaintext without the key?
</details>

<details>
<summary>Hint 3 — How is the encryption done?</summary>

It is a stream-style mode (AES-CTR). A stream cipher turns the key into a
long pseudo-random **keystream** and XORs it with your plaintext:
`C = P XOR KS`. Think about what stays the same between two different
`/api/store` calls.
</details>

<details>
<summary>Hint 4 — The fatal reuse</summary>

The service picks one key and one fixed nonce **once at startup** and reuses
both for every secret. That means every item is XORed with the *same*
keystream. This is a many-time pad. If you know one plaintext/ciphertext pair,
you know the keystream for every byte position.
</details>

<details>
<summary>Hint 5 — The full exploit</summary>

1. `POST /api/store` your own long known plaintext `P = "A" * 256`.
2. `GET /api/item/<your id>` to read back its ciphertext `C`.
3. Recover the keystream: `KS = P XOR C` (byte by byte).
4. `GET /api/item/<flag_id>` to read the flag's ciphertext `C_flag`.
5. Recover the flag: `flag = C_flag XOR KS`.

No crypto library needed — just XOR. See `sploit.py`.
</details>
