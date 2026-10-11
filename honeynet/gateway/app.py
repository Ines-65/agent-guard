"""llm-gateway: the ONLY container on attack-net with a route out (egress-net).

Attack-zone agents (victim assistant, LLM attacker) call Bedrock through it:
  POST /converse  {caller, model, messages, system?, tools?, max_tokens?}
  POST /embed     {caller, text}
  GET  /health
Controls: model allowlist (by alias), max_tokens cap, per-caller daily call cap,
global ~1 request/second pacing (hackathon quota), every call logged (metadata only).
The collector deliberately does NOT ingest gateway.jsonl: the attacker's own LLM calls
would leak ground truth to the defender.
"""
import json
import os
import threading
import time
from collections import defaultdict
from datetime import date, datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

REGION = os.environ.get("BEDROCK_REGION", "us-west-2")
# alias=model_id pairs, e.g. "fast=us.anthropic.claude-haiku-5-5"
MODELS = dict(p.split("=", 1) for p in os.environ.get("MODELS", "").split(",") if "=" in p)
EMBED_MODEL = os.environ.get("EMBED_MODEL", "amazon.titan-embed-text-v2:0")
MAX_TOKENS = int(os.environ.get("MAX_TOKENS_CAP", "1024"))
DAILY_CAP = int(os.environ.get("DAILY_CALLS_PER_CALLER", "400"))
CALLERS = set(os.environ.get("CALLERS", "victim,attacker,recon").split(","))
LOG = Path(os.environ.get("LOG_DIR", "/logs")) / "gateway.jsonl"

client = boto3.client("bedrock-runtime", region_name=REGION)
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
_lock = threading.Lock()
_last_call = 0.0
_counts: dict[tuple[str, str], int] = defaultdict(int)


class ConverseIn(BaseModel):
    caller: str
    model: str = "fast"
    messages: list
    system: str | None = None
    tools: list | None = None
    max_tokens: int | None = None


class EmbedIn(BaseModel):
    caller: str
    text: str


def log(**fields) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **fields}) + "\n")


def admit(caller: str) -> None:
    """Allowlist the caller, enforce its daily cap, and pace calls to ~1/s globally."""
    global _last_call
    if caller not in CALLERS:
        raise HTTPException(403, "unknown caller")
    key = (caller, date.today().isoformat())
    with _lock:
        if _counts[key] >= DAILY_CAP:
            raise HTTPException(429, "daily cap reached")
        _counts[key] += 1
        wait = 1.1 - (time.time() - _last_call)
        if wait > 0:
            time.sleep(wait)
        _last_call = time.time()


@app.get("/health")
def health():
    return {"status": "ok", "models": sorted(MODELS)}


@app.post("/converse")
def converse(req: ConverseIn):
    if req.model not in MODELS:
        raise HTTPException(400, f"model alias not allowed: {req.model}")
    admit(req.caller)
    kwargs = {"modelId": MODELS[req.model], "messages": req.messages,
              "inferenceConfig": {"maxTokens": min(req.max_tokens or MAX_TOKENS, MAX_TOKENS)}}
    if req.system:
        kwargs["system"] = [{"text": req.system}]
    if req.tools:
        kwargs["toolConfig"] = {"tools": req.tools}
    started = time.time()
    for attempt in range(4):
        try:
            resp = client.converse(**kwargs)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ThrottlingException" and attempt < 3:
                time.sleep(2 ** attempt)
                continue
            log(caller=req.caller, model=req.model, status="error", error=code)
            raise HTTPException(502, f"bedrock error: {code}")
    usage = resp.get("usage", {})
    log(caller=req.caller, model=req.model, status="ok", latency_s=round(time.time() - started, 2),
        input_tokens=usage.get("inputTokens"), output_tokens=usage.get("outputTokens"),
        stop_reason=resp.get("stopReason"))
    return {"output": resp["output"], "stopReason": resp.get("stopReason"), "usage": usage}


@app.post("/embed")
def embed(req: EmbedIn):
    admit(req.caller)
    resp = client.invoke_model(modelId=EMBED_MODEL, body=json.dumps({"inputText": req.text[:8000]}))
    vector = json.loads(resp["body"].read())["embedding"]
    log(caller=req.caller, model="embed", status="ok", dims=len(vector))
    return {"embedding": vector}
