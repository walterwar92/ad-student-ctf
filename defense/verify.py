#!/usr/bin/env python3
"""Defense check — the patch feedback loop for one service.

After you patch services/<svc>/app.py and restart your box, run this to confirm
BOTH halves of a good defense at once:

  SLA  = OK      -> checker put/get/check still pass (service still works)
  VULN = blocked -> the reference exploit can no longer steal a freshly planted flag

A good patch = SLA OK AND VULN blocked. If SLA breaks, your patch cost you points
even though the hole is closed; if VULN is still exploitable, keep patching.

    python defense/verify.py <service> [host] [port]
    # default host/port = your own box (team1) on the local stand

Works against any box: on the real platform point it at your team's ip + real port,
e.g.  python defense/verify.py web 10.60.1.2 5001
"""
import importlib.util
import os
import secrets
import string
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PORT = {"web": 9301, "crypto": 9401, "depot": 9501}  # team1 on the local stand
OK = 101


def _imp(svc, name):
    p = os.path.join(ROOT, "services", svc, name + ".py")
    spec = importlib.util.spec_from_file_location("%s_%s" % (name, svc), p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _gen_flag():
    return "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(31)) + "="


def main():
    if len(sys.argv) < 2:
        print("usage: python defense/verify.py <web|crypto|depot|...> [host] [port]")
        sys.exit(2)
    svc = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT.get(svc, 0)

    ch = _imp(svc, "checker")
    sp = _imp(svc, "sploit")
    flag = _gen_flag()
    print("target: %s @ %s:%d" % (svc, host, port))

    st, fid, priv = 104, None, ""
    try:
        st, fid, priv = ch.put(host, port, flag)
    except Exception as e:
        print("  [put] raised %r" % e)
    put_ok = st == OK

    get_ok = False
    if put_ok:
        try:
            get_ok = ch.get(host, port, fid, flag, priv) == OK
        except Exception as e:
            print("  [get] raised %r" % e)

    chk_ok = False
    try:
        chk_ok = ch.check(host, port) == OK
    except Exception as e:
        print("  [check] raised %r" % e)

    sla = put_ok and get_ok and chk_ok

    exploitable = False
    if put_ok and fid is not None:
        try:
            stolen = sp.exploit(host, port, fid) or []
            exploitable = flag in stolen
        except Exception as e:
            print("  [exploit] raised %r" % e)

    print("  SLA : %-7s (put=%s get=%s check=%s)" % ("OK" if sla else "BROKEN", put_ok, get_ok, chk_ok))
    print("  VULN: %s" % ("STILL EXPLOITABLE" if exploitable else "blocked"))

    if sla and not exploitable:
        verdict = "GOOD PATCH - SLA up and exploit blocked."
        code = 0
    elif sla and exploitable:
        verdict = "STILL VULNERABLE - SLA fine, but the exploit still steals. Keep patching."
        code = 1
    elif not sla and not exploitable:
        verdict = "SLA BROKEN - your patch (or a crash) broke the service. Fix functionality!"
        code = 1
    else:
        verdict = "SLA BROKEN while still exploitable - service is down/mangled."
        code = 1
    print("  => " + verdict)
    sys.exit(code)


if __name__ == "__main__":
    main()
