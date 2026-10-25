# Depot - Hints

Work through these in order. Each one reveals a little more; open the next only
when you are stuck.

<details>
<summary>Hint 1 - Where does the data live?</summary>

Every user's values are stored as real files on disk, one file per key, inside a
per-user directory. The server picks the file to open from two pieces of input:
the user that owns your token, and the key you ask for. Think about how those
two pieces are combined into a filesystem path.
</details>

<details>
<summary>Hint 2 - Compare the write path with the read path</summary>

`PUT` and `GET` are not symmetric. One of them carefully checks the key you
supply before touching disk; the other trusts it. Register one account, and try
sending the same unusual key to both commands. Which one complains, and which
one happily does what you asked?
</details>

<details>
<summary>Hint 3 - Keys are just path components</summary>

Nothing stops a key from containing path separators or `..`. If the server joins
`base/<your-user>/<key>` and then opens it, a key that climbs up and back down
lands somewhere else entirely. The flag id you are handed is literally
`<victim-user>/<victim-key>`.
</details>

<details>
<summary>Hint 4 - Build the traversal</summary>

From inside your own directory, one level up is the shared base that holds every
user's directory. So a key of the form `../<victim-user>/<victim-key>` resolves
straight into the victim's namespace. Send that as the key to `GET` with your own
valid token.
</details>

<details>
<summary>Hint 5 - Full exploit</summary>

1. `REGISTER attacker<random> <pass>` -> grab your token.
2. Split the given `flag_id` into `victim` and `key` on the first `/`.
3. `GET <token> ../<victim>/<key>`.
4. The reply `OK <flag>` is the stolen flag.

See `sploit.py` for a working reference implementation.
</details>
