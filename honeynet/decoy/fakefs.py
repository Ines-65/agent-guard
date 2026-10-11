"""Virtual filesystem for a decoy: generated base files + live overlay from /deception.

The overlay is re-read on every lookup, so a file the agent plants appears immediately
(no Cowrie-style filesystem pickle to rebuild).
"""
import posixpath
from datetime import datetime
from pathlib import Path

BASE_DIRS = ["/", "/bin", "/etc", "/home", "/opt", "/root", "/tmp", "/usr", "/usr/bin",
             "/var", "/var/log", "/var/backups", "/srv"]


def base_files(host: str, world: dict) -> dict[str, str]:
    users = [e["username"] for e in world["employees"]]
    passwd = ["root:x:0:0:root:/root:/bin/bash",
              "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
              "mysql:x:112:118:MySQL Server:/nonexistent:/bin/false"]
    passwd += [f"{u}:x:{1000 + i}:{1000 + i}::/home/{u}:/bin/bash" for i, u in enumerate(users)]
    hosts = ["127.0.0.1 localhost"] + [f"{h['ip']} {h['name']}.{world['domain']} {h['name']}"
                                      for h in world["hosts"]]
    return {
        "/etc/passwd": "\n".join(passwd) + "\n",
        "/etc/hostname": host + "\n",
        "/etc/hosts": "\n".join(hosts) + "\n",
        "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
                           'VERSION="22.04.4 LTS (Jammy Jellyfish)"\nID=ubuntu\n',
        "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n",
        "/var/log/auth.log": "",
    }


class FakeFS:
    def __init__(self, host: str, world: dict, overlay_root: Path):
        self.host = host
        self.base = base_files(host, world)
        self.overlay_root = overlay_root / "hosts" / host
        self.home_dirs = [f"/home/{e['username']}" for e in world["employees"]]

    def files(self) -> dict[str, str]:
        files = dict(self.base)
        if self.overlay_root.is_dir():
            for p in self.overlay_root.rglob("*"):
                if p.is_file():
                    vpath = "/" + p.relative_to(self.overlay_root).as_posix()
                    try:
                        files[vpath] = p.read_text()
                    except (OSError, UnicodeDecodeError):
                        files[vpath] = ""
        return files

    def dirs(self, files: dict[str, str]) -> set[str]:
        out = set(BASE_DIRS) | set(self.home_dirs)
        for path in files:
            d = posixpath.dirname(path)
            while d and d not in out:
                out.add(d)
                d = posixpath.dirname(d)
        out.add("/")
        return out

    def listdir(self, path: str) -> list[tuple[str, bool, int]] | None:
        """[(name, is_dir, size)] or None if not a directory."""
        files = self.files()
        dirs = self.dirs(files)
        if path not in dirs:
            return None
        prefix = path.rstrip("/") + "/"
        entries = {}
        for d in dirs:
            if d != path and d.startswith(prefix) and "/" not in d[len(prefix):]:
                entries[d[len(prefix):]] = (True, 4096)
        for f, content in files.items():
            if f.startswith(prefix) and "/" not in f[len(prefix):]:
                entries[f[len(prefix):]] = (False, len(content.encode()))
        return sorted((n, isdir, size) for n, (isdir, size) in entries.items())

    def read(self, path: str) -> tuple[str, str | None]:
        """('file', content) | ('dir', None) | ('missing', None)"""
        files = self.files()
        if path in files:
            return "file", files[path]
        if path in self.dirs(files):
            return "dir", None
        return "missing", None


def ls_long(entries: list[tuple[str, bool, int]], owner: str) -> str:
    stamp = datetime(2026, 10, 9, 14, 2).strftime("%b %d %H:%M")
    lines = [f"total {max(4, len(entries) * 4)}"]
    for name, is_dir, size in entries:
        mode = "drwxr-xr-x" if is_dir else "-rw-r--r--"
        lines.append(f"{mode} 2 {owner} {owner} {size:>5} {stamp} {name}")
    return "\n".join(lines)
