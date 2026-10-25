"""Serve the dashboard frontend from dashboard.html on disk.

The frontend now lives in its own file (webgui/dashboard.html) so it can be
edited with any tool/editor, independently of the Python backend. The server
reads it fresh on every request -> edit and refresh the browser, no restart.

The page is pure static HTML/CSS/JS with no server-side placeholders; it pulls
its runtime config (poll interval, token requirement) from /api/clientconfig.
"""
import os

HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")


def page():
    try:
        with open(HTML_PATH, encoding="utf-8") as f:
            return f.read()
    except Exception as e:  # noqa: BLE001
        return ("<!doctype html><meta charset=utf-8>"
                "<body style='font-family:monospace;background:#0e1116;color:#f85149;padding:40px'>"
                "dashboard.html not found or unreadable: %r</body>" % e)
