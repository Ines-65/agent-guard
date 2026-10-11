"""Fake bash: interprets a command line against the FakeFS and reports what happened.

run(line) returns (output, file_reads) so the server can log file_read events.
"""
import posixpath
import shlex

from fakefs import FakeFS, ls_long

UNAME = "Linux {host} 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"


class Shell:
    def __init__(self, fs: FakeFS, host: str, ip: str, user: str):
        self.fs, self.host, self.ip, self.user = fs, host, ip, user
        self.home = "/root" if user == "root" else f"/home/{user}"
        self.cwd = self.home
        self.history: list[str] = []
        self.closed = False

    def prompt(self) -> str:
        where = "~" if self.cwd == self.home else self.cwd
        return f"{self.user}@{self.host}:{where}$ "

    def resolve(self, arg: str) -> str:
        if arg == "~" or arg.startswith("~/"):
            arg = self.home + arg[1:]
        return posixpath.normpath(posixpath.join(self.cwd, arg))

    def run(self, line: str) -> tuple[str, list[str]]:
        line = line.strip()
        if not line:
            return "", []
        self.history.append(line)
        outputs, reads = [], []
        # sequences: ';' and '&&' (no real exit codes, so both just chain)
        for part in [p for chunk in line.split(";") for p in chunk.split("&&")]:
            out, r = self._pipeline(part.strip())
            if out:
                outputs.append(out)
            reads += r
            if self.closed:
                break
        return "\n".join(outputs), reads

    def _pipeline(self, part: str) -> tuple[str, list[str]]:
        stages = [s.strip() for s in part.split("|")]
        out, reads = self._command(stages[0])
        for stage in stages[1:]:  # only grep / head / wc are emulated after a pipe
            try:
                args = shlex.split(stage)
            except ValueError:
                return out, reads
            if args and args[0] == "grep" and len(args) > 1:
                pat = args[-1]
                flag_i = "-i" in args
                keep = (lambda l: pat.lower() in l.lower()) if flag_i else (lambda l: pat in l)
                out = "\n".join(l for l in out.splitlines() if keep(l))
            elif args and args[0] == "head":
                out = "\n".join(out.splitlines()[:10])
            elif args and args[0] == "wc":
                out = str(len(out.splitlines()))
        return out, reads

    def _command(self, cmd: str) -> tuple[str, list[str]]:
        try:
            args = shlex.split(cmd)
        except ValueError:
            return "bash: syntax error", []
        if not args:
            return "", []
        name, rest = args[0], args[1:]
        h = getattr(self, "c_" + name.replace("-", "_"), None)
        if h is None:
            return f"bash: {name}: command not found", []
        return h(rest)

    # --- commands -------------------------------------------------------------
    def c_whoami(self, a): return self.user, []
    def c_hostname(self, a): return self.host, []
    def c_pwd(self, a): return self.cwd, []
    def c_echo(self, a): return " ".join(a), []
    def c_uptime(self, a): return " 14:21:07 up 41 days,  3:12,  1 user,  load average: 0.08, 0.05, 0.01", []
    def c_history(self, a): return "\n".join(f"{i + 1:>5}  {c}" for i, c in enumerate(self.history)), []

    def c_id(self, a):
        uid = 0 if self.user == "root" else 1000
        return f"uid={uid}({self.user}) gid={uid}({self.user}) groups={uid}({self.user}),27(sudo)", []

    def c_uname(self, a):
        return (UNAME.format(host=self.host) if "-a" in a else "Linux"), []

    def c_w(self, a):
        return (" 14:21:07 up 41 days,  1 user,  load average: 0.08, 0.05, 0.01\n"
                f"USER     TTY      FROM             LOGIN@   IDLE   WHAT\n"
                f"{self.user:<8} pts/0    10.30.0.1        14:20    0.00s  w"), []

    def c_ip(self, a):
        return ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
                f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet {self.ip}/24 brd 10.30.0.255 scope global eth0"), []

    def c_ifconfig(self, a):
        return f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet {self.ip}  netmask 255.255.255.0", []

    def c_ps(self, a):
        procs = ["root         1  0.0  0.1 /sbin/init", "root       612  0.0  0.2 /usr/sbin/sshd -D",
                 "root       640  0.0  0.1 /usr/sbin/cron -f"]
        if "db" in self.host:
            procs.append("mysql      911  1.2  9.8 /usr/sbin/mysqld")
        if "jump" in self.host:
            procs.append("admin     1204  0.3  2.1 node /opt/app/server.js")
        return "USER       PID %CPU %MEM COMMAND\n" + "\n".join(procs), []

    def c_netstat(self, a):
        lines = ["tcp   0  0 0.0.0.0:22     0.0.0.0:*  LISTEN"]
        if "db" in self.host:
            lines.append("tcp   0  0 127.0.0.1:3306 0.0.0.0:*  LISTEN")
        if "jump" in self.host:
            lines.append("tcp   0  0 0.0.0.0:8080   0.0.0.0:*  LISTEN")
        return "Proto Recv-Q Send-Q Local Address Foreign Address State\n" + "\n".join(lines), []

    c_ss = c_netstat

    def c_env(self, a):
        return (f"USER={self.user}\nHOME={self.home}\nSHELL=/bin/bash\nPWD={self.cwd}\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nLANG=C.UTF-8"), []

    def c_cd(self, a):
        target = self.resolve(a[0]) if a else self.home
        kind, _ = self.fs.read(target)
        if kind != "dir":
            return f"bash: cd: {a[0] if a else target}: No such file or directory", []
        self.cwd = target
        return "", []

    def c_ls(self, a):
        flags = "".join(x[1:] for x in a if x.startswith("-"))
        paths = [x for x in a if not x.startswith("-")] or [self.cwd]
        outs = []
        for p in paths:
            path = self.resolve(p)
            entries = self.fs.listdir(path)
            if entries is None:
                kind, content = self.fs.read(path)
                if kind == "file":
                    outs.append(p)
                    continue
                outs.append(f"ls: cannot access '{p}': No such file or directory")
                continue
            if "a" not in flags:
                entries = [e for e in entries if not e[0].startswith(".")]
            owner = self.user if path.startswith("/home") else "root"
            body = ls_long(entries, owner) if "l" in flags else "  ".join(e[0] for e in entries)
            outs.append((f"{p}:\n" if len(paths) > 1 else "") + body)
        return "\n".join(outs), []

    def c_cat(self, a):
        outs, reads = [], []
        for p in [x for x in a if not x.startswith("-")]:
            path = self.resolve(p)
            kind, content = self.fs.read(path)
            if kind == "file":
                outs.append(content.rstrip("\n"))
                reads.append(path)
            elif kind == "dir":
                outs.append(f"cat: {p}: Is a directory")
            else:
                outs.append(f"cat: {p}: No such file or directory")
        return "\n".join(outs), reads

    c_more = c_less = c_head = c_tail = c_cat

    def c_find(self, a):
        start = self.resolve(a[0]) if a and not a[0].startswith("-") else self.cwd
        files = self.fs.files()
        hits = sorted(p for p in files if p.startswith(start.rstrip("/") + "/") or p == start)
        if "-name" in a:
            idx = a.index("-name")
            pat = a[idx + 1].strip("*") if idx + 1 < len(a) else ""
            hits = [p for p in hits if pat in posixpath.basename(p)]
        return "\n".join(hits), []

    def c_grep(self, a):
        args = [x for x in a if not x.startswith("-")]
        if len(args) < 2:
            return "", []
        pat, targets = args[0], args[1:]
        files = self.fs.files()
        recursive = any(x.startswith("-") and ("r" in x or "R" in x) for x in a)
        outs, reads = [], []
        for t in targets:
            path = self.resolve(t)
            cands = ([p for p in files if p.startswith(path.rstrip("/") + "/")] if recursive
                     else [path] if path in files else [])
            for f in sorted(cands):
                matched = [l for l in files[f].splitlines() if pat.lower() in l.lower()]
                if matched:
                    reads.append(f)
                    outs += [f"{f}:{l}" if recursive else l for l in matched]
        return "\n".join(outs), reads

    def c_sudo(self, a):
        return f"[sudo] password for {self.user}: \nSorry, user {self.user} may not run sudo on {self.host}.", []

    c_su = c_sudo

    def c_ssh(self, a):
        target = next((x for x in a if not x.startswith("-")), "host")
        return f"ssh: connect to host {target.split('@')[-1]} port 22: Connection timed out", []

    def c_scp(self, a): return "ssh: connect to host port 22: Connection timed out", []
    def c_curl(self, a): return "curl: (7) Failed to connect: Connection refused", []
    def c_wget(self, a): return "wget: unable to connect: Connection refused", []

    def c_mysql(self, a):
        return "ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)", []

    def c_mysqldump(self, a): return "mysqldump: Got error: 2002: Can't connect to local MySQL server", []

    def c_exit(self, a):
        self.closed = True
        return "logout", []

    c_logout = c_exit
