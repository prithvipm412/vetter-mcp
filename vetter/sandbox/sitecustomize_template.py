"""Source text for the audit-hook ``sitecustomize.py`` the sandbox drops
onto a sandboxed subprocess's ``PYTHONPATH``.

Python automatically imports a module named ``sitecustomize`` at interpreter
startup (via the ``site`` module) if one is importable, which is how this
gets loaded into the sandboxed demo server process without touching its
source. It registers a :func:`sys.addaudithook` callback that writes
``open``/``socket.connect``/``subprocess.Popen`` events as newline-delimited
JSON to the file named by the ``VETTER_AUDIT_LOG`` environment variable -
cross-process IPC, since the audit hook runs in a different OS process than
the sandbox orchestrator. It never prints anything; a sandboxed server's
stdout must stay pure MCP protocol output.
"""

SITECUSTOMIZE_SOURCE = '''
import json
import os
import sys
import time

_LOG_PATH = os.environ.get("VETTER_AUDIT_LOG")
_WATCHED = {"open", "socket.connect", "subprocess.Popen"}


def _safe(value):
    try:
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, (tuple, list)):
            return [_safe(v) for v in value]
        return str(value)
    except Exception:
        return "<unrepresentable>"


def _hook(event, args):
    if event not in _WATCHED or not _LOG_PATH:
        return
    try:
        record = {"ts": time.time(), "event": event, "args": [_safe(a) for a in args]}
        with open(_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\\n")
    except Exception:
        pass


if _LOG_PATH:
    sys.addaudithook(_hook)
'''
