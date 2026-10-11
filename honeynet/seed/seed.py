"""One-shot seeder, runs at `docker compose up` before the decoys start.

- (optional) resets Mongo collections, /deception, /control and the log files
- generates this run's canaries (Mongo registry only)
- renders starting breadcrumbs into /deception/hosts/<host>/<path>
- renders wiki pages into /deception/wiki/<slug>.md
- writes per-host accounts to /control/userdb/<host>.json and service flags
- records every planted file as a decoy (policy "seed")
"""
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from pymongo import MongoClient

from canaries import generate_registry, render

HERE = Path(__file__).parent
TEMPLATES = Path(os.environ.get("TEMPLATES_DIR", HERE / "templates"))
WORLD = Path(os.environ.get("WORLD_MODEL", HERE.parent / "world_model.json"))
ACCOUNTS = Path(os.environ.get("ACCOUNTS", HERE / "accounts.json"))
DECEPTION = Path(os.environ.get("DECEPTION_DIR", "/deception"))
CONTROL = Path(os.environ.get("CONTROL_DIR", "/control"))
LOG_DIRS = [Path(p) for p in os.environ.get("LOG_DIRS", "/logs-cowrie:/logs-trap").split(":") if p]
RESET_COLLECTIONS = ["events", "decoys", "actions", "summaries", "sessions", "canaries",
                     "counters", "collector_offsets", "approvals"]


def next_id(db, name: str, prefix: str, width: int) -> str:
    doc = db.counters.find_one_and_update({"_id": name}, {"$inc": {"seq": 1}},
                                          upsert=True, return_document=True)
    return f"{prefix}-{doc['seq']:0{width}d}"


def clear_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        shutil.rmtree(child) if child.is_dir() else child.unlink()


def reset(db) -> None:
    for name in RESET_COLLECTIONS:
        db[name].drop()
    clear_dir(DECEPTION)
    clear_dir(CONTROL)
    for log_dir in LOG_DIRS:
        log_dir.mkdir(parents=True, exist_ok=True)
        for f in log_dir.glob("*.jsonl"):
            f.write_text("")  # truncate; the collector notices the shrink and restarts at 0


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def seed(db, run_id=None, do_reset=True) -> dict:
    if do_reset:
        reset(db)
    world = json.loads(WORLD.read_text())
    now = datetime.now(timezone.utc).isoformat()

    registry_docs = generate_registry(run_id)
    registry = {c["canary_id"]: c["value"] for c in registry_docs}
    planted: dict[str, list[str]] = {cid: [] for cid in registry}
    decoys = []

    def add_decoy(host, kind, vpath, text, used):
        decoy_id = next_id(db, "decoy", "dec", 4)
        for cid in used:
            planted[cid].append(decoy_id)
        decoys.append({
            "decoy_id": decoy_id, "run_id": run_id, "session_id": None, "host": host,
            "kind": kind, "path": vpath, "policy": "seed", "canaries": used,
            "size_bytes": len(text.encode()),
            "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "reason": "Starting breadcrumb planted for every attacker", "evidence": [],
            "created_at": now, "touched_by": [],
        })

    # host files: templates/hosts/<host>/<virtual path>
    for tpl in sorted((TEMPLATES / "hosts").rglob("*")):
        if not tpl.is_file():
            continue
        host, *rel = tpl.relative_to(TEMPLATES / "hosts").parts
        vpath = "/" + "/".join(rel)
        text, used = render(tpl.read_text(), registry, world)
        out = DECEPTION / "hosts" / host / Path(*rel)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text)
        add_decoy(host, "credential" if used else "file", vpath, text, used)

    # wiki pages: templates/wiki/<slug>.md -> /deception/wiki/<slug>.md
    for tpl in sorted((TEMPLATES / "wiki").glob("*.md")):
        text, used = render(tpl.read_text(), registry, world)
        out = DECEPTION / "wiki" / tpl.name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text)
        add_decoy("wiki", "wiki_page", f"/wiki/{tpl.stem}", text, used)

    # accounts per host (values rendered; read by the decoys at each login)
    accounts = json.loads(ACCOUNTS.read_text())
    for host, users in accounts.items():
        rendered = [{"user": u["user"],
                     "passwords": [render(p, registry, world)[0] for p in u["passwords"]]}
                    for u in users]
        write_json(CONTROL / "userdb" / f"{host}.json", rendered)

    # service flags: hosts with min_tier > 1 start closed (opened by escalate_tier later)
    write_json(CONTROL / "services.json",
               {h["name"]: h.get("min_tier", 1) <= 1 for h in world["hosts"]})
    write_json(CONTROL / "run.json", {"run_id": run_id, "seeded_at": now})

    for c in registry_docs:
        c["planted_in"] = planted[c["canary_id"]]
    db.canaries.insert_many(registry_docs)
    if decoys:
        db.decoys.insert_many(decoys)
    db.decoys.create_index([("host", 1), ("path", 1)])
    db.events.create_index("event_id", unique=True)
    db.events.create_index([("session_id", 1), ("ts", 1)])
    return {"decoys": len(decoys), "canaries": len(registry_docs)}


if __name__ == "__main__":
    client = MongoClient(os.environ.get("MONGO_URI", "mongodb://mongo:27017"))
    db = client[os.environ.get("MONGO_DB", "maya")]
    run_id = os.environ.get("RUN_ID") or None
    result = seed(db, run_id=run_id, do_reset=os.environ.get("SEED_RESET", "1") == "1")
    print(f"seeded: {result}, run_id={run_id}")
