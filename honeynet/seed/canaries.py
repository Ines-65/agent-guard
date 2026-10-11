"""Canary generation and placeholder rendering (shared by seed and, later, maya-control).

Templates and LLM output only ever contain placeholders:
  {{canary:<id>}}  -> replaced by the canary value from the registry
  {{ip:<host>}}    -> replaced by the host's IP from the world model
Real-looking values exist only at runtime (Mongo + /control), never in git.
"""
import re
import secrets
import string
from datetime import datetime, timezone

PLACEHOLDER = re.compile(r"\{\{(canary|ip):([a-z0-9_.-]+)\}\}")

# canary id -> kind (kind must match schemas/canary.json)
CANARY_SET = {
    "aws_1": "aws",
    "awssecret_1": "aws",
    "apitoken_1": "api_token",
    "db_1": "db_password",
    "ssh_1": "ssh_password",
    "ftp_1": "ssh_password",
}


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def make_value(canary_id: str) -> str:
    """Realistic-looking but random value, unique per run."""
    if canary_id.startswith("awssecret"):
        return _rand(string.ascii_letters + string.digits + "/+", 40)
    if canary_id.startswith("aws"):
        return "AKIA" + _rand(string.ascii_uppercase + "234567", 16)
    if canary_id.startswith("apitoken"):
        return "hel_live_" + _rand("0123456789abcdef", 32)
    # passwords: memorable shape, random core so they are unique and matchable
    return "Helio-" + _rand(string.ascii_letters + string.digits, 8) + "!"


def generate_registry(run_id=None) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    return [
        {"canary_id": f"canary:{cid}", "kind": kind, "value": make_value(cid),
         "run_id": run_id, "planted_in": [], "created_at": now, "first_used_event": None}
        for cid, kind in CANARY_SET.items()
    ]


def render(text: str, registry: dict, world: dict) -> tuple[str, list[str]]:
    """Replace placeholders. Returns (rendered_text, canary_ids_used).

    registry: {"canary:db_1": "value", ...}; unknown placeholders raise KeyError
    so a typo in a template fails loudly instead of leaking a raw placeholder.
    """
    ips = {h["name"]: h["ip"] for h in world["hosts"]}
    used: list[str] = []

    def sub(m: re.Match) -> str:
        kind, key = m.group(1), m.group(2)
        if kind == "ip":
            return ips[key]
        cid = f"canary:{key}"
        used.append(cid)
        return registry[cid]

    return PLACEHOLDER.sub(sub, text), sorted(set(used))
