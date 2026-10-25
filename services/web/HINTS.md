# SecureNotes - progressive hints

Try to get as far as you can before opening each hint. They are ordered from
gentle nudges to a near-complete walkthrough.

<details>
<summary>Hint 1 - where to look</summary>

Four of the five endpoints are boring CRUD. One endpoint takes attacker
controlled text and does something interesting with it server-side. Which
endpoint reflects your input into a database operation?
</details>

<details>
<summary>Hint 2 - the shape of the bug</summary>

Think about how a search feature turns your `q` into a `WHERE ... LIKE ...`
clause. What happens if your `q` is not an ordinary word but contains SQL
metacharacters like a single quote `'` or a parenthesis `)`?
</details>

<details>
<summary>Hint 3 - confirm the injection</summary>

Register an account, create a note, then search. Compare the responses for:

- `q=hello`
- `q='`  (a lone single quote)

If the lone quote makes the endpoint error out (HTTP 400 / "bad query") while
a normal word works, the query is being built by string concatenation and your
input is landing inside the SQL.
</details>

<details>
<summary>Hint 4 - the injection point in detail</summary>

The query looks roughly like:

```
... WHERE user_id=<you> AND (title LIKE '%<q>%' OR body LIKE '%<q>%')
```

Your `q` is placed between `'%` and `%'`. To break out you must close the
string literal **and** the open parenthesis before adding your own SQL, then
comment out the trailing `%'...` with `-- `.
</details>

<details>
<summary>Hint 5 - UNION the whole table</summary>

The endpoint returns three columns: `id`, `title`, `body`. That is perfect for
a 3-column `UNION SELECT`. Add a `UNION SELECT id,title,body FROM notes` to
read **every** user's notes, not just your own.
</details>

<details>
<summary>Hint 6 - working payload</summary>

Send this as the `q` parameter (URL-encode it so the client does not mangle it):

```
zzz%') UNION SELECT id,title,body FROM notes-- -
```

The resulting query becomes:

```
SELECT id,title,body FROM notes WHERE user_id=<you> AND (title LIKE '%zzz%')
UNION SELECT id,title,body FROM notes
```

Every note body in the database comes back in the `notes` array. The flags are
stored as note bodies, so filter the results with the flag regex
`[A-Z0-9]{31}=` and you are done. See `sploit.py` for a reference
implementation.
</details>

<details>
<summary>Hint 7 - defending (for the defense side)</summary>

Switch the search query to a parameterized statement with `?` placeholders and
pass the wildcards as bound parameters. Full fix in `solution.md`.
</details>
