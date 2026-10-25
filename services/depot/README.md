# Depot

Depot is a small file-backed key/value store. Every user gets a private
namespace; you register an account, authenticate to receive a token, and then
store and retrieve your own string values under named keys.

## Connecting

Depot speaks a plain, newline-delimited UTF-8 text protocol over raw TCP.

```
nc <host> 5003
```

Send one command per line (terminated with `\n`). The server answers with one
line per command (unless noted). Keys and values contain no spaces or newlines.

## Protocol

| Command | Response |
| --- | --- |
| `REGISTER <user> <pass>` | `OK <token>` on success, `ERR exists` if the name is taken |
| `AUTH <user> <pass>` | `OK <token>` on success, `ERR badcreds` otherwise |
| `PUT <token> <key> <value>` | `OK` (stores `<value>` under `<key>` for the token's user) |
| `GET <token> <key>` | `OK <value>`, or `ERR notfound` |
| `LIST <token>` | `OK <k1,k2,...>` (your own keys, comma-separated) |
| `PING` | `PONG` |
| `QUIT` | `BYE`, then the connection closes |

- A `<token>` is issued by `REGISTER` / `AUTH` and must accompany every
  `PUT` / `GET` / `LIST`.
- Usernames and keys are expected to be simple identifiers.

## Example session

```
REGISTER alice hunter2
OK 6f1e...c3
PUT 6f1e...c3 note hello-world
OK
LIST 6f1e...c3
OK note
GET 6f1e...c3 note
OK hello-world
PING
PONG
QUIT
BYE
```

## Scoring

The game's checksystem will `REGISTER` a fresh account each round and `PUT` a
flag under a random key in that account's namespace. Keep the service answering
correctly for your own teams's traffic; find a way to read the flags belonging
to the other teams' accounts.
