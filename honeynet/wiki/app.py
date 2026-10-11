"""Fake internal wiki. Serves Markdown pages from /deception/wiki/<slug>.md.

Every request is logged to /logs/wiki.jsonl. New pages written by the agent appear
immediately (files are read on each request).
"""
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import markdown
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

PAGES = Path(os.environ.get("DECEPTION_DIR", "/deception")) / "wiki"
LOG = Path(os.environ.get("LOG_DIR", "/logs")) / "wiki.jsonl"
SLUG = re.compile(r"^[a-z0-9-]{1,64}$")
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><title>{title} - Helio Wiki</title>
<style>body{{font-family:sans-serif;max-width:800px;margin:2em auto;color:#222}}
code{{background:#eee;padding:0 4px}}nav a{{margin-right:1em}}</style></head>
<body><nav><a href="/">Helio Wiki</a></nav>{body}</body></html>"""


def log(request: Request, status: int, page: str | None) -> None:
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "source": "wiki", "host": "wiki",
           "src_ip": request.client.host if request.client else None, "method": request.method,
           "path": request.url.path, "page": page, "status": status,
           "user_agent": request.headers.get("user-agent", "")[:200]}
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps(rec) + "\n")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    pages = sorted(p.stem for p in PAGES.glob("*.md")) if PAGES.is_dir() else []
    items = "".join(f'<li><a href="/wiki/{p}">{p.replace("-", " ").title()}</a></li>' for p in pages)
    log(request, 200, None)
    return TEMPLATE.format(title="Home", body=f"<h1>Helio Wiki</h1><ul>{items}</ul>")


@app.get("/wiki/{slug}", response_class=HTMLResponse)
def page(slug: str, request: Request):
    path = PAGES / f"{slug}.md"
    if not SLUG.match(slug) or not path.is_file():
        log(request, 404, slug)
        return HTMLResponse(TEMPLATE.format(title="Not found", body="<h1>Page not found</h1>"), 404)
    text = path.read_text()
    title = text.splitlines()[0].lstrip("# ").strip() if text else slug
    log(request, 200, slug)
    return TEMPLATE.format(title=title, body=markdown.markdown(text))


@app.api_route("/{rest:path}", methods=["GET", "POST", "PUT", "DELETE"])
def other(rest: str, request: Request):
    log(request, 404, None)
    return HTMLResponse(TEMPLATE.format(title="Not found", body="<h1>Page not found</h1>"), 404)
