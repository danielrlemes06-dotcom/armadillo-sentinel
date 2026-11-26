import json
from datetime import datetime, timezone

# Mapeamento dos eventos do Cowrie para os tipos usados no Sentinel.
# login.success = o honeypot aceitou a senha do atacante, nao e um login legitimo.
EVENT_MAP = {
    "cowrie.login.failed": "login_failed",
    "cowrie.login.success": "honeypot_login",
    "cowrie.command.input": "command",
}


def _parse_time(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def parse_cowrie_line(line, source="cowrie"):
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    event_type = EVENT_MAP.get(data.get("eventid"))
    if not event_type or not data.get("src_ip") or not data.get("timestamp"):
        return None
    try:
        event_time = _parse_time(data["timestamp"])
    except ValueError:
        return None
    return {
        "event_time": event_time,
        "source_ip": data["src_ip"],
        "username": data.get("username"),
        "service": "cowrie",
        "event_type": event_type,
        "raw_line": line,
        "source": source,
    }


def parse_cowrie_file(path):
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_cowrie_line(line)
            if event:
                events.append(event)
    return events
