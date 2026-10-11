"""Maya Agentic dashboard - Phase 1: live sessions, events and trap hits."""
import os
import pandas as pd
import streamlit as st
from pymongo import MongoClient

st.set_page_config(page_title="Maya Agentic", layout="wide")
st_autorefresh = getattr(st, "autorefresh", None)
st.title("Maya Agentic")


@st.cache_resource
def get_db():
    return MongoClient(os.environ.get("MONGO_URI", "mongodb://mongo:27017"),
                       serverSelectionTimeoutMS=3000)[os.environ.get("MONGO_DB", "maya")]


try:
    db = get_db()
    db.command("ping")
except Exception as exc:
    st.error(f"MongoDB not reachable: {exc}")
    st.stop()

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Sessions", db.sessions.count_documents({}))
c2.metric("Events", db.events.count_documents({}))
c3.metric("Trap hits", db.events.count_documents({"decoy_id": {"$ne": None}}))
c4.metric("Canary uses", db.events.count_documents({"event_type": "canary_use"}))
c5.metric("Decoys planted", db.decoys.count_documents({}))

st.subheader("Techniques observed")
techs = sorted({e["technique"] for e in db.events.find({"technique": {"$ne": None}}, {"technique": 1})})
st.write(", ".join(techs) if techs else "none yet")

st.subheader("Recent events")
rows = list(db.events.find({}, {"_id": 0, "ts": 1, "session_id": 1, "host": 1,
                               "event_type": 1, "technique": 1, "untrusted_content": 1}).sort("ts", -1).limit(40))
if rows:
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
else:
    st.info("No events yet. Seed the honeynet and run the crawler.")
