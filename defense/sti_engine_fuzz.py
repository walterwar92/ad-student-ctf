#!/usr/bin/env python3
"""Reproduce the StillAttached engine crash in isolation (sandbox copy).

The web talks to the engine as newline-delimited JSON, one command per TCP
connection, adding an "owner" field. We do the same directly against a SANDBOX
engine (never the live one) to find the minimal attach/read_reg/detach sequence
that SIGSEGVs it. A crash shows up as the connection being refused/reset.

Run on the box AFTER starting a sandbox engine on some port, e.g.:
    sudo docker run -d --rm --name sti-sbx -e ENGINE_PORT=31337 \
         -p 127.0.0.1:31338:31337 stillattached-engine:latest
    python3 defense/sti_engine_fuzz.py 127.0.0.1 31338 replay 200

modes:
    sanity        one clean cycle (new_session/new_target/attach/threads/read_reg/note)
    replay        realistic 10.61.2.5 loop: new_target->attach->threads->read_reg*->detach
    attach_only   new_target->attach, repeated (no reads)
    readreg_loop  attach one target, then read_reg in a tight loop
    detach_uaf    new_target->attach->detach then read_reg/threads on the detached session
    attach_foreign attach to ids the owner does not own (owner/owner2 mix)
"""
import json
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 31338
MODE = sys.argv[3] if len(sys.argv) > 3 else "replay"
ITERS = int(sys.argv[4]) if len(sys.argv) > 4 else 200
OWNER = int(sys.argv[5]) if len(sys.argv) > 5 else 1

REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rip"]


class EngineDown(Exception):
    pass


def rpc(d, timeout=3.0):
    """One command per connection, like the web. Raise EngineDown if the
    engine is not answering (crash / mid-restart)."""
    try:
        s = socket.create_connection((HOST, PORT), timeout)
    except OSError as e:
        raise EngineDown("connect: %s" % e)
    try:
        s.settimeout(timeout)
        s.sendall(json.dumps(d).encode() + b"\n")
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                raise EngineDown("closed without reply to %s" % d.get("command"))
            buf += chunk
            if len(buf) > 1 << 20:
                break
    except OSError as e:
        raise EngineDown("io: %s" % e)
    finally:
        try:
            s.close()
        except OSError:
            pass
    try:
        return json.loads(buf.split(b"\n", 1)[0])
    except ValueError:
        raise EngineDown("bad json: %r" % buf[:80])


def alive():
    try:
        rpc({"command": "new_session", "owner": OWNER})
        return True
    except EngineDown:
        return False


def result(resp):
    return resp.get("result") if isinstance(resp, dict) else None


def new_session(owner=OWNER):
    r = result(rpc({"command": "new_session", "owner": owner}))
    return r.get("session") if isinstance(r, dict) else None


def new_target(sid, owner=OWNER, name="x"):
    r = result(rpc({"command": "new_target", "owner": owner, "session": sid, "name": name}))
    return r.get("target") if isinstance(r, dict) else None


def cmd(sid, command, owner=OWNER, **kw):
    return rpc(dict(command=command, owner=owner, session=sid, **kw))


def sanity():
    sid = new_session()
    print("session:", sid)
    tid = new_target(sid)
    print("target:", tid)
    print("attach:", cmd(sid, "attach", id=tid))
    print("threads:", cmd(sid, "threads"))
    print("read_reg rax:", cmd(sid, "read_reg", tid=0, reg="rax"))
    print("note set:", cmd(sid, "note", tid=0, data="41424344"))
    print("note get:", cmd(sid, "note", tid=0))
    print("detach:", cmd(sid, "detach"))


def guarded(step_fn):
    """Run step_fn(i) ITERS times; stop at first crash and report."""
    done = 0
    try:
        for i in range(ITERS):
            step_fn(i)
            done += 1
    except EngineDown as e:
        print("*** ENGINE DOWN after %d ops: %s" % (done, e))
        time.sleep(1.5)
        print("alive again after restart:", alive())
        return done
    print("no crash in %d iterations (mode=%s)" % (ITERS, MODE))
    return None


def main():
    print("target %s:%d mode=%s iters=%d owner=%d" % (HOST, PORT, MODE, ITERS, OWNER))
    if not alive():
        print("engine not reachable at start"); return
    if MODE == "sanity":
        sanity(); return

    if MODE == "replay":
        sid = new_session()
        def step(i):
            tid = new_target(sid, name="r%d" % i)
            cmd(sid, "attach", id=tid)
            cmd(sid, "threads")
            for r in REGS:
                cmd(sid, "read_reg", tid=0, reg=r)
            cmd(sid, "detach")
        guarded(step)

    elif MODE == "attach_only":
        sid = new_session()
        def step(i):
            tid = new_target(sid, name="a%d" % i)
            cmd(sid, "attach", id=tid)
        guarded(step)

    elif MODE == "readreg_loop":
        sid = new_session(); tid = new_target(sid); cmd(sid, "attach", id=tid); cmd(sid, "threads")
        def step(i):
            cmd(sid, "read_reg", tid=0, reg=REGS[i % len(REGS)])
        guarded(step)

    elif MODE == "detach_uaf":
        sid = new_session()
        def step(i):
            tid = new_target(sid, name="d%d" % i)
            cmd(sid, "attach", id=tid)
            cmd(sid, "detach")
            cmd(sid, "read_reg", tid=0, reg="rip")   # use after detach
            cmd(sid, "threads")
        guarded(step)

    elif MODE == "attach_foreign":
        sid = new_session(OWNER)
        sid2 = new_session(OWNER + 1)
        tid2 = new_target(sid2, OWNER + 1, name="victim")
        print("victim target (owner %d): %s" % (OWNER + 1, tid2))
        def step(i):
            cmd(sid, "attach", owner=OWNER, id=(tid2 or 1))
            cmd(sid, "read_reg", tid=0, reg="rip")
        guarded(step)

    else:
        print("unknown mode:", MODE)


if __name__ == "__main__":
    main()
