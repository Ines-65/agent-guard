"""Fake internal billing API used as a canary endpoint.

It accepts any request, logs it in full to /logs/canary.jsonl and answers like a real
API would. It does NOT know the canary values: the collector (defense zone) matches
logged requests against the registry, so no secret lives in the attack zone.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

LOG = Path(os.environ.get("LOG_DIR", "/logs")) / "canary.jsonl"
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.api_route("/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def catch_all(rest: str, request: Request):
    body = (await request.body())[:4096].decode("utf-8", "replace")
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "source": "canary", "host": "billing-api",
           "src_ip": request.client.host if request.client else None, "method": request.method,
           "path": "/" + rest, "query": str(request.url.query), "headers": headers, "body": body}
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    if rest.endswith("health"):
        return {"status": "ok", "service": "helio-billing", "version": "1.8.2"}
    if "authorization" not in {k.lower() for k in headers}:
        return JSONResponse({"error": "missing bearer token"}, status_code=401)
    return JSONResponse({"error": "token expired, rotate via ops"}, status_code=403)
