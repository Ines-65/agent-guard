"""Command -> MITRE ATT&CK technique (Linux shell). Maya's own table is Windows-oriented,
so this is a Linux table based on build plan section 10. First match wins."""
import re

RULES: list[tuple[str, str, float]] = [
    (r"\b(history\s+-c|unset\s+HISTFILE)", "T1070.003", 0.9),
    (r"\bcrontab\b", "T1053.003", 0.8),
    (r"\bmysqldump\b|\bcp\b.*\.(sql|db|sqlite)\b", "T1005", 0.8),
    (r"\b(tar|zip|gzip)\b", "T1560.001", 0.6),
    (r"\b(wget|curl)\b.*\b(-o|-O|>)", "T1105", 0.7),
    (r"\b(cat|grep|less|more|head|tail)\b.*(\.env|passw|cred|secret|\.key|id_rsa|token|notes)", "T1552.001", 0.9),
    (r"\bgrep\b.*-r.*(pass|key|token|secret)", "T1552.001", 0.9),
    (r"\bcat\b.*/etc/passwd", "T1087.001", 0.9),
    (r"\b(ip\s+a|ip\s+addr|ifconfig|cat\s+/etc/hosts)", "T1016", 0.9),
    (r"\b(netstat|ss)\b", "T1049", 0.9),
    (r"\b(uname|cat\s+/etc/os-release|hostname)\b", "T1082", 0.9),
    (r"\b(whoami|id|w)\b", "T1033", 0.8),
    (r"\bps\b", "T1057", 0.8),
    (r"\b(ls|find)\b", "T1083", 0.6),
    (r"\b(sudo|su)\b", "T1548.003", 0.6),
    (r"\b(ssh|scp)\b", "T1021.004", 0.7),
    (r"\b(wget|curl)\b", "T1105", 0.5),
]
_COMPILED = [(re.compile(p), t, c) for p, t, c in RULES]
CRED_PATH = re.compile(r"(\.env|passw|cred|secret|\.key|id_rsa|token|notes|backup\.sh|readme)", re.I)


def map_command(text: str | None) -> tuple[str | None, float | None, str]:
    if not text:
        return None, None, "unknown"
    for rx, technique, conf in _COMPILED:
        if rx.search(text):
            return technique, conf, "pattern"
    return None, None, "unknown"


def map_file_read(path: str) -> tuple[str, float, str]:
    return ("T1552.001", 0.9, "pattern") if CRED_PATH.search(path) else ("T1005", 0.6, "pattern")
