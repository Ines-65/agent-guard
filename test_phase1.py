"""End-to-end Phase 1 test, no Docker: seed -> run decoys in-process -> crawler attacks ->
collector normalizes logs -> assert events, sessions, canary hits and decoy touches."""
import asyncio, json, os, tempfile, sys, time
from pathlib import Path
import mongomock

ROOT = Path(__file__).parent
for p in ["honeynet/seed", "honeynet/decoy", "honeynet/wiki", "collector", "attackers", "ai_traps/canary"]:
    sys.path.insert(0, str(ROOT / p))

tmp = Path(tempfile.mkdtemp())
DECEPTION = tmp / "deception"; CONTROL = tmp / "control"; LOGS = tmp / "logs"
LOGS.mkdir(); (tmp / "logs-trap").mkdir()
os.environ.update(DECEPTION_DIR=str(DECEPTION), CONTROL_DIR=str(CONTROL),
                  LOG_DIRS=f"{LOGS}:{tmp/'logs-trap'}", WORLD_MODEL=str(ROOT/"honeynet/world_model.json"),
                  TEMPLATES_DIR=str(ROOT/"honeynet/seed/templates"), ACCOUNTS=str(ROOT/"honeynet/seed/accounts.json"),
                  EVENT_SCHEMA=str(ROOT/"schemas/event.json"), COWRIE_LOGS=str(LOGS), TRAP_LOGS=str(tmp/"logs-trap"))

db = mongomock.MongoClient().maya
import seed as seed_mod
res = seed_mod.seed(db, run_id="r-001", do_reset=True)
print("seed:", res)
assert res["decoys"] >= 8 and res["canaries"] == 6
world = json.loads((ROOT/"honeynet/world_model.json").read_text())

# sanity: no raw canary value sits in a rendered breadcrumb path that also names it (placeholders resolved)
env_txt = (DECEPTION/"hosts/fake-jump-01/opt/app/.env").read_text()
assert "{{" not in env_txt, "unresolved placeholder in .env"
assert "AKIA" in env_txt, "aws canary not rendered"

# --- run three decoys in-process on localhost ports -------------------------
import asyncssh
from fakefs import FakeFS
from shell import Shell
import importlib.util
spec = importlib.util.spec_from_file_location("decoymod", ROOT/"honeynet/decoy/decoy.py")

HOSTS = [("fake-jump-01","10.30.0.11",2201),("fake-db-01","10.30.0.12",2202),("fake-ftp-01","10.30.0.13",2203)]

def load_userdb(host):
    return json.loads((CONTROL/"userdb"/f"{host}.json").read_text())
services = json.loads((CONTROL/"services.json").read_text())

def make_server(host, ip, logf):
    import secrets
    from datetime import datetime, timezone
    fs = FakeFS(host, world, DECEPTION)
    def log(eventid, session, src_ip, **kw):
        rec={"ts":datetime.now(timezone.utc).isoformat(),"host":host,"eventid":eventid,"session":session,"src_ip":src_ip,**kw}
        with open(logf,"a") as f: f.write(json.dumps(rec)+"\n")
    class S(asyncssh.SSHServer):
        def connection_made(self,c): self.c=c; self.sid=secrets.token_hex(6); self.ip=(c.get_extra_info("peername") or ["?"])[0]; c.set_extra_info(sid=self.sid,sip=self.ip); log("cowrie.session.connect",self.sid,self.ip)
        def connection_lost(self,e): log("cowrie.session.closed",self.sid,self.ip)
        def begin_auth(self,u): return True
        def password_auth_supported(self): return True
        def validate_password(self,u,pw):
            ok = services.get(host,True) and any(a["user"]==u and pw in a["passwords"] for a in load_userdb(host))
            log("cowrie.login.success" if ok else "cowrie.login.failed",self.sid,self.ip,username=u,password=pw)
            return ok
    async def handle(proc):
        sid=proc.get_extra_info("sid"); sip=proc.get_extra_info("sip")
        sh=Shell(fs,host,ip,proc.get_extra_info("username"))
        def ex(line):
            log("cowrie.command.input",sid,sip,input=line)
            out,reads=sh.run(line)
            for pth in reads: log("decoy.file_read",sid,sip,path=pth,input=line)
            return out
        if proc.command:
            o=ex(proc.command); proc.stdout.write(o+"\n" if o else "")
        else:
            while not sh.closed:
                proc.stdout.write(sh.prompt()); line=await proc.stdin.readline()
                if not line: break
                o=ex(line.rstrip("\r\n"));
                if o: proc.stdout.write(o+"\n")
        proc.exit(0)
    return S, handle

async def run_all():
    servers=[]
    for host,ip,port in HOSTS:
        S,handle=make_server(host,ip,LOGS/f"{host}.jsonl")
        key=asyncssh.generate_private_key("ssh-ed25519")
        servers.append(await asyncssh.create_server(S,"127.0.0.1",port,server_host_keys=[key],process_factory=handle))
    # crawler: patch asyncssh.connect so host IPs map to localhost ports
    import crawler as cr
    real_connect=asyncssh.connect
    portmap={ip:port for _,ip,port in HOSTS}
    async def patched(ip,*a,**kw):
        kw["known_hosts"]=None
        kw["port"]=portmap.get(ip,kw.get("port",22))
        return await real_connect("127.0.0.1",**kw)
    cr.asyncssh.connect=patched
    # wiki fetch: serve files directly instead of HTTP
    async def fake_fetch(self,url):
        if url in self.fetched_urls: return
        self.fetched_urls.add(url); self.count+=1
        import re as _re
        m=_re.search(r"/wiki/([a-z0-9-]+)",url)
        if m:
            f=DECEPTION/"wiki"/f"{m.group(1)}.md"
            if f.is_file(): self.harvest(f.read_text())
    cr.Crawler.fetch=fake_fetch
    c=cr.Crawler("10.30.0.11","fake-jump-01",seed=1,port=2201,max_commands=60,wiki_base="http://10.30.0.20")
    steps=await c.run()
    for s in servers: s.close()
    return c,steps

c,steps=asyncio.run(run_all())
print(f"crawler: {len(steps)} steps, hosts={sorted(c.ip_to_host[i] for i in c.visited_hosts if i in c.ip_to_host)}, creds_found={len(c.creds)}")
time.sleep(0.2)

# --- collector ---------------------------------------------------------------
import collector as col
os.environ["COWRIE_LOGS"]=str(LOGS); os.environ["TRAP_LOGS"]=str(tmp/"logs-trap")
C=col.Collector(db)
total=0
for _ in range(3):
    total+=C.poll_once(); time.sleep(0.1)
events=list(db.events.find())
by_type={}
for e in events: by_type[e["event_type"]]=by_type.get(e["event_type"],0)+1
print(f"collector: {len(events)} events {by_type}")
print(f"sessions: {db.sessions.count_documents({})}")
tech=sorted({e['technique'] for e in events if e.get('technique')})
print(f"techniques observed: {tech}")
touched=db.decoys.count_documents({"touched_by.0":{"$exists":True}})
print(f"decoys touched: {touched}/{db.decoys.count_documents({})}")
canary_events=db.events.count_documents({"event_type":"canary_use"})
print(f"canary_use events: {canary_events}")
# assertions
assert len(events)>20, "too few events"
assert db.sessions.count_documents({})<=4, "sessions not grouped (pivot created new attacker)"
assert "T1552.001" in tech, "credential-in-file technique not detected"
assert touched>=2, "no decoys registered as touched"
# no raw canary value stored anywhere in events
reg=[c["value"] for c in db.canaries.find()]
blob=json.dumps(events, default=str)
leaked=[v for v in reg if v in blob]
assert not leaked, f"canary value leaked into events: {leaked}"
# password never stored
assert "admin123" not in blob and "Helio-" not in blob, "a secret leaked into events"
print("\nALL PHASE 1 CHECKS PASSED")
