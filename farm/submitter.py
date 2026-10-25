"""Submitter — the only thing that talks to the jury. Runs on its OWN schedule,
independent of collector rounds, so freshly stolen flags go out immediately.

Smart bits:
  * token bucket enforces the jury's flags/min and flags/submit caps
  * AIMD auto-tune: ramp the rate up while clean, halve it the moment the jury
    signals rate-limit — the farm finds the real ceiling by itself
  * global backoff when the jury says "game not started / paused"
  * per-flag state machine with TTL + bounded retries (never resubmits forever,
    never resubmits a settled flag)

Transports: HTTP (POST/PUT, JSON array or newline text) and TCP line protocol.
"""
import json
import re
import socket
import time
import urllib.error
import urllib.request

import runtime
import store
import verdicts

_PAUSED_RE = re.compile(r"(?i)not started|is paused|game over|game is not|can.?t submit|try later")


class TokenBucket:
    def __init__(self, per_min):
        self.rate = max(1.0, float(per_min))
        self.tokens = self.rate
        self.ts = time.time()

    def refill(self):
        now = time.time()
        self.tokens = min(self.rate, self.tokens + (now - self.ts) * self.rate / 60.0)
        self.ts = now

    def available(self):
        self.refill()
        return int(self.tokens)

    def consume(self, n):
        self.tokens = max(0.0, self.tokens - n)


# --------------------------------------------------------------- transports --
def _submit_http(s, flags, log):
    method = s.get("method", "PUT")
    headers = {s.get("token_header", "X-Team-Token"): s.get("token", "")}
    if s.get("json_body"):
        body = json.dumps(flags).encode()
        headers["Content-Type"] = "application/json"
    else:
        body = ("\n".join(flags) + "\n").encode()
    req = urllib.request.Request(s["url"], data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=s.get("timeout", 10)) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace")
    except Exception as ex:  # noqa: BLE001
        log.warning("submit http error: %r" % ex)
        return ""


def _submit_tcp(s, flags, log):
    try:
        with socket.create_connection((s["host"], s["port"]), timeout=s.get("timeout", 10)) as c:
            c.settimeout(s.get("timeout", 10))
            f = c.makefile("rwb")
            for _ in range(s.get("greeting_lines", 0)):
                f.readline()
            if s.get("send_token_first") and s.get("token"):
                f.write((s["token"] + "\n").encode())
                f.flush()
                for _ in range(s.get("token_reply_lines", 0)):
                    f.readline()
            lines = []
            if s.get("batch", True):
                for fl in flags:
                    f.write((fl + "\n").encode())
                f.flush()
                for _ in range(len(flags)):
                    ln = f.readline()
                    if not ln:
                        break
                    lines.append(ln.decode("utf-8", "replace").strip())
            else:
                for fl in flags:
                    f.write((fl + "\n").encode())
                    f.flush()
                    ln = f.readline()
                    lines.append(ln.decode("utf-8", "replace").strip() if ln else "")
            return "\n".join(lines)
    except Exception as ex:  # noqa: BLE001
        log.warning("submit tcp error: %r" % ex)
        return ""


def _transport(cfg, flags, log):
    s = cfg["submitter"]
    if s.get("mode") == "tcp":
        return _submit_tcp(s, flags, log)
    return _submit_http(s, flags, log)


# ------------------------------------------------------- one batch of flags --
def _apply(cfg, flags, text, log):
    """Classify a response and drive each flag through the state machine.
    Returns a per-class count summary and whether the jury throttled/paused us."""
    ttl = cfg.get("flag_lifetime_seconds", 150)
    retry = cfg.get("retry", {"max_tries": 40, "backoff": [2, 5, 10, 30]})
    backoff = retry.get("backoff", [2, 5, 10, 30])
    max_tries = retry.get("max_tries", 40)
    res = verdicts.classify_response(flags, text, cfg)
    now = time.time()
    summ = {"accepted": 0, "drop": 0, "resubmit": 0, "unknown": 0}
    for f, r in res.items():
        cls, raw = r["cls"], r["raw"]
        summ[cls] = summ.get(cls, 0) + 1
        if cls == "accepted":
            row = store.get_flag(f)
            store.set_status(f, store.ACCEPTED, verdict=raw)
            if row and row.get("target"):
                store.bump_target(row["target"], accepted=1)
        elif cls == "drop":
            store.set_status(f, store.REJECTED, verdict=raw)
        else:  # resubmit | unknown -> keep, bounded
            row = store.get_flag(f)
            tries = (row["tries"] if row else 0) + 1
            first = row["first"] if row else now
            if (now - first) > ttl or tries > max_tries:
                store.set_status(f, store.EXPIRED, verdict=raw)
            else:
                nb = backoff[min(tries - 1, len(backoff) - 1)]
                store.set_status(f, store.QUEUED, next_try=now + nb, verdict=raw, inc_tries=True)
    vc = store.meta_get("verdict_counts", {})
    for k, n in summ.items():
        vc[k] = vc.get(k, 0) + n
    store.meta_set("verdict_counts", vc)
    paused = bool(_PAUSED_RE.search(text or ""))
    throttled = summ["resubmit"] > 0 and summ["resubmit"] >= max(1, len(flags) // 2)
    return summ, paused, throttled


def _aimd(cfg, throttled, clean):
    """Additive-increase / multiplicative-decrease on the live submit rate."""
    if not cfg.get("submitter", {}).get("autotune", True):
        return
    rate = runtime.get("flags_per_min")
    floor = cfg["submitter"].get("min_flags_per_min", 30)
    ceil = cfg["submitter"].get("max_flags_per_min", max(rate * 4, 240))
    step = cfg["submitter"].get("rate_step", max(10, rate * 0.1))
    if throttled:
        rate = max(floor, rate * 0.5)
    elif clean:
        rate = min(ceil, rate + step)
    runtime.set("flags_per_min", round(rate, 1))


def submit_tick(cfg, bucket, log):
    """One pass of the submit loop. Returns flags submitted this pass."""
    if not runtime.submit_allowed():
        return 0
    bucket.rate = max(1.0, float(runtime.get("flags_per_min")))
    tokens = bucket.available()
    if tokens < 1:
        return 0
    per = min(cfg.get("limits", {}).get("flags_per_submit", 100), tokens)
    flags = store.claim_for_submit(per, order=runtime.get("order", "newest_first"))
    if not flags:
        return 0
    bucket.consume(len(flags))
    text = _transport(cfg, flags, log)
    summ, paused, throttled = _apply(cfg, flags, text, log)
    if paused:
        gb = cfg["submitter"].get("global_backoff", 15)
        runtime.backoff_submit(gb)
        log.info("jury says game paused/not started -> backoff %ss" % gb)
        store.log_event("WARN", "submit", "game paused -> backoff %ss" % gb)
    else:
        _aimd(cfg, throttled, clean=(summ["accepted"] > 0 and summ["resubmit"] == 0))
    log.info("submit %d -> %s | rate=%s/min | store=%s"
             % (len(flags), summ, runtime.get("flags_per_min"), store.stats()))
    if summ["accepted"]:
        store.log_event("INFO", "submit", "+%d accepted" % summ["accepted"], summ)
    return len(flags)


def run_loop(cfg, log, stop_event, dry=False):
    """Submitter thread entry. Honors runtime pause/backoff; tops up continuously."""
    if dry:
        log.info("[dry-run] submitter disabled; flags only queued")
        return
    bucket = TokenBucket(runtime.get("flags_per_min"))
    last_maint = 0
    ttl = cfg.get("flag_lifetime_seconds", 150)
    max_tries = cfg.get("retry", {}).get("max_tries", 40)
    while not stop_event.is_set():
        try:
            n = submit_tick(cfg, bucket, log)
            now = time.time()
            if now - last_maint > 20:
                exp = store.expire_stale(ttl, max_tries)
                if exp:
                    log.info("expired %d stale flag(s)" % exp)
                last_maint = now
        except Exception as e:  # noqa: BLE001
            log.error("submit loop error: %r" % e)
            n = 0
        stop_event.wait(0.3 if n else 1.0)


def drain_once(cfg, log, max_passes=200):
    """--once: flush the queue in batches, respecting rate, then return."""
    bucket = TokenBucket(runtime.get("flags_per_min"))
    gap = cfg.get("limits", {}).get("min_seconds_between_submits", 0.3)
    sent = 0
    for _ in range(max_passes):
        n = submit_tick(cfg, bucket, log)
        if not n:
            break
        sent += n
        if gap:
            time.sleep(gap)
    log.info("drain: submitted %d | store=%s" % (sent, store.stats()))
    return sent
