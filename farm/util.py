"""Logging + small helpers for the farm (stdlib only)."""
import logging
import os
import re
import sys

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "farm.log")


def get_logger():
    lg = logging.getLogger("farm")
    if lg.handlers:
        return lg
    lg.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    lg.addHandler(sh)
    try:
        fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
        fh.setFormatter(fmt)
        lg.addHandler(fh)
    except Exception:
        pass
    return lg


def flag_re(cfg):
    return re.compile(cfg["flag_regex"])
