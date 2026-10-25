"""Turn a submitter's response into a per-flag verdict class.

Classes:
  accepted  jury said OK                         -> ACCEPTED (points), never retried
  drop      invalid / own / too-old / duplicate  -> REJECTED,  never retried
  resubmit  rate-limited / queued / game-not-started -> keep, retry later
  unknown   no / garbled response                -> keep, retry later (bounded)

Handles three response shapes:
  * ForcAD JSON list of {"flag","msg","status":bool}  (status bool is authoritative)
  * generic JSON (list/dict) echoing the flag + a message
  * plain newline text ("<flag> ACCEPTED")
"""
import json
import re

CLASSES = ("accepted", "drop", "resubmit")


def classify_line(line, verdicts):
    for name in CLASSES:
        pat = verdicts.get(name)
        if pat and re.search(pat, line):
            return name
    return "unknown"


def classify_response(flags, text, cfg):
    """Return {flag: {"cls": <class>, "raw": <verdict text>}} for every flag sent."""
    fre = re.compile(cfg["flag_regex"])
    verdicts = cfg["verdicts"]
    out = {}
    text = text or ""
    try:
        j = json.loads(text)
    except Exception:
        j = None

    items = None
    if isinstance(j, list):
        items = j
    elif isinstance(j, dict):
        for key in ("flags", "responses", "results"):
            if isinstance(j.get(key), list):
                items = j[key]
                break
        if items is None:
            items = [{"flag": k, "msg": v} for k, v in j.items()]

    if items is not None:
        for it in items:
            if isinstance(it, dict):
                blob = " ".join(str(v) for v in it.values())
                fl = it.get("flag")
                if not fl:
                    m = fre.search(blob)
                    fl = m.group(0) if m else None
                if "status" in it and isinstance(it["status"], bool):
                    # ForcAD: status bool is authoritative; msg only splits drop vs resubmit
                    if it["status"]:
                        cls = "accepted"
                    else:
                        cls = classify_line(str(it.get("msg", blob)), verdicts)
                        if cls in ("accepted", "unknown"):
                            cls = "resubmit" if re.search(
                                verdicts.get("resubmit", "x^"), blob) else "drop"
                else:
                    cls = classify_line(blob, verdicts)
            else:
                blob = str(it)
                m = fre.search(blob)
                fl = m.group(0) if m else None
                cls = classify_line(blob, verdicts)
            if fl:
                out[fl] = {"cls": cls, "raw": _short(blob)}
    else:
        for ln in text.splitlines():
            m = fre.search(ln)
            if m:
                out[m.group(0)] = {"cls": classify_line(ln, verdicts), "raw": _short(ln)}

    for f in flags:
        out.setdefault(f, {"cls": "unknown", "raw": _short(text)})
    return out


def looks_like_game_paused(text, verdicts):
    """Whole batch rejected with a 'game not started / paused' style message?"""
    pat = verdicts.get("resubmit")
    return bool(pat and re.search(pat, text or ""))


def _short(s):
    s = " ".join((s or "").split())
    return s[:120]
