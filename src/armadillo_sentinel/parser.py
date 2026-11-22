import re
from datetime import datetime

LINE_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

IP = r"(?P<ip>[0-9a-fA-F:.]+)"
PATTERNS = [
    ("login_failed", re.compile(r"Failed \w+ for (?:invalid user )?(?P<user>\S+) from " + IP)),
    ("login_success", re.compile(r"Accepted \w+ for (?P<user>\S+) from " + IP)),
    ("invalid_user", re.compile(r"Invalid user (?P<user>\S+) from " + IP)),
]


def parse_line(line, year, source="auth.log"):
    m = LINE_RE.match(line.rstrip("\r\n"))
    if not m:
        return None
    for event_type, pattern in PATTERNS:
        hit = pattern.search(m["msg"])
        if hit:
            ts = datetime.strptime(
                f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
            )
            return {
                "event_time": ts,
                "source_ip": hit["ip"],
                "username": hit["user"],
                "service": m["proc"],
                "event_type": event_type,
                "raw_line": line.rstrip("\r\n"),
                "source": source,
            }
    return None


def parse_file(path, year=None, source="auth.log"):
    year = year or datetime.now().year
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line, year, source)
            if event:
                events.append(event)
    return events
