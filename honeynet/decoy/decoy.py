"""Decoy SSH server (one container per fake host).

Logs Cowrie-style JSON lines to /logs/<host>.jsonl:
  cowrie.session.connect, cowrie.login.success, cowrie.login.failed,
  cowrie.command.input, decoy.file_read, cowrie.session.closed
Accounts are read from /control/userdb/<host>.json at each login; a host listed as
closed in /control/services.json rejects every login (opened later by escalate_tier).
"""
import asyncio
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

import asyncssh

from fakefs import FakeFS
from shell import Shell

HOST = os.environ["DECOY_HOST"]
IP = os.environ.get("DECOY_IP", "10.30.0.10")
PORT = int(os.environ.get("DECOY_PORT", "22"))
WORLD = json.loads(Path(os.environ.get("WORLD_MODEL", "/world_model.json")).read_text())
DECEPTION = Path(os.environ.get("DECEPTION_DIR", "/deception"))
CONTROL = Path(os.environ.get("CONTROL_DIR", "/control"))
LOG = Path(os.environ.get("LOG_DIR", "/logs")) / f"{HOST}.jsonl"
BANNER = "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\n\n"

FS = FakeFS(HOST, WORLD, DECEPTION)


def log(eventid: str, session: str, src_ip: str, **fields) -> None:
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "host": HOST, "eventid": eventid,
           "session": session, "src_ip": src_ip, **fields}
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps(rec) + "\n")


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return default


def check_login(user: str, password: str) -> tuple[bool, str | None]:
    if not load_json(CONTROL / "services.json", {}).get(HOST, True):
        return False, "service_closed"
    for account in load_json(CONTROL / "userdb" / f"{HOST}.json", []):
        if account["user"] == user and password in account["passwords"]:
            return True, None
    return False, None


class DecoyServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        self.conn = conn
        self.session = secrets.token_hex(6)
        self.src_ip = (conn.get_extra_info("peername") or ("?",))[0]
        conn.set_extra_info(decoy_session=self.session, decoy_src=self.src_ip)
        log("cowrie.session.connect", self.session, self.src_ip)

    def connection_lost(self, exc):
        log("cowrie.session.closed", self.session, self.src_ip)

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        ok, note = check_login(username, password)
        log("cowrie.login.success" if ok else "cowrie.login.failed", self.session, self.src_ip,
            username=username, password=password, **({"note": note} if note else {}))
        return ok


async def handle(process: asyncssh.SSHServerProcess) -> None:
    session = process.get_extra_info("decoy_session")
    src_ip = process.get_extra_info("decoy_src")
    shell = Shell(FS, HOST, IP, process.get_extra_info("username"))

    def execute(line: str) -> str:
        log("cowrie.command.input", session, src_ip, input=line[:4096])
        out, reads = shell.run(line)
        for path in reads:
            log("decoy.file_read", session, src_ip, path=path, input=line[:4096])
        return out

    try:
        if process.command:  # exec request: `ssh host 'cmd'`
            out = execute(process.command)
            process.stdout.write(out + ("\n" if out else ""))
        else:  # interactive shell
            process.stdout.write(BANNER)
            while not shell.closed:
                process.stdout.write(shell.prompt())
                line = await process.stdin.readline()
                if not line:
                    break
                out = execute(line.rstrip("\r\n"))
                if out:
                    process.stdout.write(out + "\n")
    except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged, ConnectionError):
        pass
    process.exit(0)


async def main() -> None:
    key = asyncssh.generate_private_key("ssh-ed25519")
    await asyncssh.create_server(DecoyServer, "", PORT, server_host_keys=[key],
                                 process_factory=handle, server_version="OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
    print(f"decoy {HOST} listening on {PORT}", flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
