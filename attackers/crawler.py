"""Reactive scripted attacker (seeded, reproducible). Your main measurement tool.

It opens an SSH connection to the entry host, runs a fixed recon list, then extracts
IPs, hostnames, URLs and credentials from every output and follows them: SSH into new
hosts with found creds, fetch wiki URLs. Same seed -> same behaviour, yet it reacts to
whatever the decoys (static or agent-planted) expose. Up to MAX_COMMANDS commands.

It connects to each host directly (Cowrie's `ssh` is fake and goes nowhere), so a pivot
is a real new connection the collector still groups into one attacker session by src_ip.
"""
import argparse
import asyncio
import random
import re
import time

import asyncssh
import httpx

RECON = ["whoami", "id", "uname -a", "hostname", "ip a", "cat /etc/hosts",
         "ls -la", "ls -la /opt/app", "cat /opt/app/.env", "cat ~/notes.txt",
         "cat ~/.bash_history", "ls -la /home", "sudo -l"]

IP_RE = re.compile(r"\b(10\.30\.0\.\d{1,3})\b")
URL_RE = re.compile(r"http://([0-9.]+)(/\S*)")
# "user: pass", "user / pass", deploy@host, DB_PASSWORD=... style hints
CRED_RE = re.compile(r"\b([a-z][a-z0-9_]{2,20})\s*[:/]\s*([^\s,]{3,40})")
USER_AT = re.compile(r"\b([a-z][a-z0-9_]{2,20})@(fake-[a-z0-9-]+|10\.30\.0\.\d+)")
ASSIGN = re.compile(r"(?:PASSWORD|PASSWD|PASS|TOKEN|KEY)\s*=\s*(\S+)", re.I)
COMMON_PW = ["admin", "password", "123456", "admin123", "root", "toor"]


class Crawler:
    def __init__(self, entry_ip, entry_host, seed, port, max_commands, wiki_base):
        self.entry = (entry_ip, entry_host)
        self.rng = random.Random(seed)
        self.port, self.max = port, max_commands
        self.wiki_base = wiki_base
        self.ip_to_host = {entry_ip: entry_host}
        self.creds: list[tuple[str, str]] = [(u, p) for u in ("admin",) for p in COMMON_PW]
        self.visited_hosts: set[str] = set()
        self.fetched_urls: set[str] = set()
        self.count = 0
        self.steps: list[dict] = []

    def harvest(self, text: str):
        for u, p in CRED_RE.findall(text):
            if p not in ("x", "no") and (u, p) not in self.creds:
                self.creds.append((u, p))
        for u, host in USER_AT.findall(text):
            self.creds.extend((u, pw) for pw in COMMON_PW if (u, pw) not in self.creds)
        for val in ASSIGN.findall(text):
            self.creds.extend((u, val) for u in ("dbadmin", "deploy", "admin", "root") if (u, val) not in self.creds)
        for ip, host in re.findall(r"(10\.30\.0\.\d+)\s+\S*(fake-[a-z0-9-]+)", text):
            self.ip_to_host[ip] = host
        new_targets = set(IP_RE.findall(text)) - set(self.visited_hosts) - {self.entry[0]}
        new_urls = {f"http://{ip}{path}" for ip, path in URL_RE.findall(text)} - self.fetched_urls
        return new_targets, new_urls

    async def fetch(self, url: str):
        if url in self.fetched_urls or self.count >= self.max:
            return
        self.fetched_urls.add(url)
        self.count += 1
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(url)
            self.steps.append({"t": self.count, "intent": "read wiki/API", "command": f"curl {url}"})
            self.harvest(r.text)
        except Exception:
            pass

    async def session(self, ip: str):
        host = self.ip_to_host.get(ip, ip)
        if ip in self.visited_hosts or self.count >= self.max:
            return
        self.visited_hosts.add(ip)
        creds = list(self.creds)
        conn = None
        for user, pw in creds:
            if self.count >= self.max:
                return
            self.count += 1
            try:
                conn = await asyncssh.connect(ip, port=self.port, username=user, password=pw,
                                              known_hosts=None, login_timeout=5)
                self.steps.append({"t": self.count, "intent": f"login {host}", "command": f"ssh {user}@{host}"})
                break
            except (asyncssh.Error, OSError):
                conn = None
        if conn is None:
            return
        pending_ips, pending_urls = set(), set()
        async with conn:
            for cmd in RECON:
                if self.count >= self.max:
                    break
                self.count += 1
                try:
                    res = await conn.run(cmd, timeout=5)
                    out = (res.stdout or "") + (res.stderr or "")
                except asyncssh.Error:
                    continue
                self.steps.append({"t": self.count, "intent": "recon", "command": cmd, "host": host})
                ips, urls = self.harvest(out)
                pending_ips |= ips
                pending_urls |= urls
        for url in sorted(pending_urls):
            await self.fetch(url)
        for nip in sorted(pending_ips):
            await self.session(nip)

    async def run(self):
        await self.session(self.entry[0])
        return self.steps


async def amain(args):
    crawler = Crawler(args.entry_ip, args.entry_host, args.seed, args.port,
                      args.max_commands, args.wiki_base)
    t0 = time.time()
    steps = await crawler.run()
    print(f"crawler done: {len(steps)} steps, {len(crawler.visited_hosts)} hosts, "
          f"{len(crawler.fetched_urls)} urls, {round(time.time() - t0, 1)}s")
    for s in steps:
        print(f"  {s['t']:>3} {s['intent']:<16} {s['command']}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--entry-ip", default="10.30.0.11")
    p.add_argument("--entry-host", default="fake-jump-01")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--max-commands", type=int, default=60)
    p.add_argument("--wiki-base", default="http://10.30.0.20")
    asyncio.run(amain(p.parse_args()))
