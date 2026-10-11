"""Collector: tails decoy and trap logs (read-only), normalizes each line into an event
(schemas/event.json) and stores it in Mongo.

- session_id: one att-XXXX per (run_id, src_ip or agent_id); a pivot to another host stays
  in the same session, conn_id keeps the raw per-connection id
- canaries: any registry value found in a login, command or HTTP request becomes a
  canary_use event; the value is replaced by {{canary:<id>}} before storage
- passwords are never stored in events
- decoys: file reads / wiki pages matching a decoy get decoy_id, and the decoy's
  touched_by list is updated
- gateway.jsonl is skipped on purpose (attacker LLM calls would leak ground truth)
"""
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator
from pymongo import MongoClient, ReturnDocument

from attack_mapping import map_command, map_file_read

INPUT_DIRS = {"cowrie-logs": Path(os.environ.get("COWRIE_LOGS", "/in/cowrie")),
              "trap-logs": Path(os.environ.get("TRAP_LOGS", "/in/trap"))}
SKIP_FILES = {"gateway.jsonl"}
CONTROL = Path(os.environ.get("CONTROL_DIR", "/control"))
SCHEMA = json.loads(Path(os.environ.get("EVENT_SCHEMA", "/schemas/event.json")).read_text())
VALIDATOR = Draft202012Validator(SCHEMA)
MAX_CONTENT = 4096

DECOY_TYPES = {
    "cowrie.login.success": "login",
    "cowrie.login.failed": "login_failed",
    "cowrie.command.input": "command",
    "decoy.file_read": "file_read",
    "cowrie.session.closed": "session_end",
}


class Collector:
    def __init__(self, db):
        self.db = db
        self._registry: dict[str, str] = {}
        self._registry_at = 0.0

    # --- helpers --------------------------------------------------------------
    def next_id(self, name: str, prefix: str, width: int) -> str:
        doc = self.db.counters.find_one_and_update({"_id": name}, {"$inc": {"seq": 1}},
                                                   upsert=True, return_document=ReturnDocument.AFTER)
        return f"{prefix}-{doc['seq']:0{width}d}"

    def run_id(self):
        try:
            return json.loads((CONTROL / "run.json").read_text()).get("run_id")
        except (OSError, json.JSONDecodeError):
            return None

    def registry(self) -> dict[str, str]:
        """value -> canary_id, refreshed every 5 s."""
        if time.time() - self._registry_at > 5:
            self._registry = {c["value"]: c["canary_id"] for c in self.db.canaries.find({}, {"value": 1, "canary_id": 1})}
            self._registry_at = time.time()
        return self._registry

    def scrub(self, text: str | None) -> tuple[str | None, list[str]]:
        """Replace canary values by placeholders; return (clean_text, canary_ids_found)."""
        if not text:
            return text, []
        found = []
        for value, cid in self.registry().items():
            if value and value in text:
                text = text.replace(value, "{{" + cid + "}}")
                found.append(cid)
        return text, found

    def session_for(self, run_id, key: str | None, ts: str) -> str:
        key = key or "unknown"
        doc = self.db.sessions.find_one({"run_id": run_id, "key": key})
        if doc:
            self.db.sessions.update_one({"_id": doc["_id"]}, {"$set": {"last_ts": ts}})
            return doc["session_id"]
        sid = self.next_id("session", "att", 4)
        self.db.sessions.insert_one({"session_id": sid, "run_id": run_id, "key": key,
                                     "first_ts": ts, "last_ts": ts})
        return sid

    def find_decoy(self, host: str, path: str | None):
        if not path:
            return None
        return self.db.decoys.find_one({"host": host, "path": path}, {"decoy_id": 1})

    # --- normalization --------------------------------------------------------
    def normalize(self, rec: dict, raw_ref: str) -> list[dict]:
        run_id = self.run_id()
        ts = rec.get("ts") or datetime.now(timezone.utc).isoformat()
        base = {"ts": ts, "run_id": run_id, "host": rec.get("host"), "agent_id": None,
                "src_ip": rec.get("src_ip"), "user": None, "untrusted_content": None,
                "decoy_id": None, "canary_id": None, "technique": None,
                "technique_confidence": None, "classification_method": "unknown",
                "owasp_agentic": [], "raw_ref": raw_ref}
        events: list[dict] = []
        source = rec.get("source", "cowrie")
        canaries: list[str] = []

        if source == "cowrie":
            etype = DECOY_TYPES.get(rec.get("eventid"))
            if etype is None:
                return []
            ev = dict(base, source="cowrie", conn_id=rec.get("session"), event_type=etype)
            if etype in ("login", "login_failed"):
                ev["user"] = rec.get("username")
                _, canaries = self.scrub(rec.get("password"))  # password itself is never stored
                note = f" ({rec['note']})" if rec.get("note") else ""
                ev["untrusted_content"] = f"ssh login user={rec.get('username')}{note}"
                if canaries and etype == "login":
                    ev.update(technique="T1078", technique_confidence=0.95, classification_method="exact")
            elif etype in ("command", "file_read"):
                ev["untrusted_content"], canaries = self.scrub(rec.get("input"))
                if etype == "file_read":
                    ev["untrusted_content"] = f"read {rec.get('path')}"
                    decoy = self.find_decoy(rec.get("host"), rec.get("path"))
                    ev["decoy_id"] = decoy["decoy_id"] if decoy else None
                    t, c, m = map_file_read(rec.get("path", ""))
                else:
                    t, c, m = map_command(ev["untrusted_content"])
                ev.update(technique=t, technique_confidence=c, classification_method=m)
            events.append(ev)

        elif source in ("wiki", "canary"):
            ev = dict(base, source=source, conn_id=None, event_type="http_request")
            if source == "wiki":
                ev["untrusted_content"] = f"{rec.get('method')} {rec.get('path')} -> {rec.get('status')}"
                if rec.get("page"):
                    decoy = self.find_decoy("wiki", f"/wiki/{rec['page']}")
                    ev["decoy_id"] = decoy["decoy_id"] if decoy else None
            else:
                blob = json.dumps({"query": rec.get("query"), "headers": rec.get("headers"),
                                   "body": rec.get("body")})
                clean, canaries = self.scrub(blob)
                ev["untrusted_content"] = f"{rec.get('method')} {rec.get('path')} {clean}"
            events.append(ev)
        else:
            return []

        for ev in events:
            ev["session_id"] = self.session_for(run_id, ev["src_ip"] or ev["agent_id"], ts)
            if ev["untrusted_content"]:
                ev["untrusted_content"] = ev["untrusted_content"][:MAX_CONTENT]

        for cid in canaries:  # one extra canary_use event per canary found in this line
            primary = events[0]
            events.append(dict(primary, event_type="canary_use", canary_id=cid,
                               untrusted_content=f"canary {cid} used via {primary['event_type']}",
                               technique="T1078" if primary["source"] == "cowrie" else "T1552.001",
                               technique_confidence=0.95, classification_method="exact",
                               owasp_agentic=["ASI03"] if primary["source"] == "canary" else []))
        return events

    def store(self, events: list[dict]) -> int:
        stored = 0
        for ev in events:
            ev["event_id"] = self.next_id("event", "evt", 6)
            errors = sorted(VALIDATOR.iter_errors(ev), key=str)
            if errors:
                print(f"invalid event dropped ({errors[0].message}): {ev.get('raw_ref')}", flush=True)
                continue
            self.db.events.insert_one(dict(ev))
            if ev.get("decoy_id"):
                self.db.decoys.update_one({"decoy_id": ev["decoy_id"]}, {"$addToSet": {"touched_by": ev["event_id"]}})
            if ev["event_type"] == "canary_use":
                self.db.canaries.update_one({"canary_id": ev["canary_id"], "first_used_event": None},
                                            {"$set": {"first_used_event": ev["event_id"]}})
            stored += 1
        return stored

    # --- tailing --------------------------------------------------------------
    def poll_once(self) -> int:
        total = 0
        for vol, folder in INPUT_DIRS.items():
            if not folder.is_dir():
                continue
            for path in sorted(folder.glob("*.jsonl")):
                if path.name in SKIP_FILES:
                    continue
                total += self.read_new(vol, path)
        return total

    def read_new(self, vol: str, path: Path) -> int:
        key = f"{vol}/{path.name}"
        state = self.db.collector_offsets.find_one({"_id": key}) or {"offset": 0, "line": 0}
        size = path.stat().st_size
        if size < state["offset"]:  # file was truncated (reset): start again
            state = {"offset": 0, "line": 0}
        if size == state["offset"]:
            return 0
        with path.open("rb") as f:
            f.seek(state["offset"])
            chunk = f.read()
        complete, _, _partial = chunk.rpartition(b"\n")
        if not complete and not chunk.endswith(b"\n"):
            return 0  # only a partial line so far
        lines = complete.split(b"\n") if complete else []
        stored, line_no = 0, state["line"]
        for raw in lines:
            line_no += 1
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            stored += self.store(self.normalize(rec, f"{key}:{line_no}"))
        new_offset = state["offset"] + len(complete) + 1
        self.db.collector_offsets.update_one({"_id": key}, {"$set": {"offset": new_offset, "line": line_no}}, upsert=True)
        return stored


def main() -> None:
    db = MongoClient(os.environ.get("MONGO_URI", "mongodb://mongo:27017"))[os.environ.get("MONGO_DB", "maya")]
    collector = Collector(db)
    print("collector running", flush=True)
    while True:
        try:
            n = collector.poll_once()
            if n:
                print(f"stored {n} events", flush=True)
        except Exception as exc:  # keep running; one bad line must not stop collection
            print(f"collector error: {exc}", flush=True)
        time.sleep(1)


if __name__ == "__main__":
    main()
