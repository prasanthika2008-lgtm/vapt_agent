"""Append-only audit trail (JSON Lines). Every action is attributable."""
import json
import os
from datetime import datetime, timezone

LOG = os.path.join(os.path.dirname(__file__), "audit_log.jsonl")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(actor: str, action: str, detail: dict | str = ""):
    rec = {"ts": now(), "actor": actor, "action": action, "detail": detail}
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def read_all():
    if not os.path.exists(LOG):
        return []
    with open(LOG, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]
