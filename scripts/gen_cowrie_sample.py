import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
lines = []
USERS = ["root", "admin", "ubuntu", "test", "oracle"]
PASSWORDS = ["123456", "admin", "password", "root", "toor", "qwerty"]


def sid():
    return "%012x" % random.getrandbits(48)


def emit(ts, ip, session, eventid, **extra):
    data = {
        "eventid": eventid,
        **extra,
        "sensor": "honeypot",
        "timestamp": ts.isoformat(timespec="microseconds") + "Z",
        "src_ip": ip,
        "session": session,
    }
    lines.append((ts, json.dumps(data, separators=(",", ":"))))


def connect(ts, ip, session):
    port = random.randint(30000, 60000)
    emit(ts, ip, session, "cowrie.session.connect", src_port=port, dst_port=2222,
         message=f"New connection: {ip}:{port} (10.0.0.5:2222) [session: {session}]")


def failed(ts, ip, session, user, pw):
    emit(ts, ip, session, "cowrie.login.failed", username=user, password=pw,
         message=f"login attempt [{user}/{pw}] failed")


def success(ts, ip, session, user, pw):
    emit(ts, ip, session, "cowrie.login.success", username=user, password=pw,
         message=f"login attempt [{user}/{pw}] succeeded")


def command(ts, ip, session, cmd):
    emit(ts, ip, session, "cowrie.command.input", input=cmd, message=f"CMD: {cmd}")


# A: forca bruta (40 tentativas em ~3 min), consegue entrar e executa comandos
ip, s = "192.0.2.10", sid()
t0 = datetime(2026, 11, 24, 3, 10, 0, 123456)
connect(t0, ip, s)
for i in range(40):
    failed(t0 + timedelta(seconds=1 + i * 4), ip, s, USERS[i % 5], random.choice(PASSWORDS))
t_ok = t0 + timedelta(seconds=1 + 40 * 4)
success(t_ok, ip, s, "root", "toor")
for j, cmd in enumerate(["uname -a", "cat /proc/cpuinfo", "whoami", "ls -la /tmp"]):
    command(t_ok + timedelta(seconds=3 + j * 2), ip, s, cmd)

# B: scanner lento (12 conexoes, uma a cada 10 minutos)
ip = "192.0.2.20"
for i in range(12):
    s = sid()
    t = datetime(2026, 11, 25, 14, 0, 0, 500000) + timedelta(minutes=i * 10)
    connect(t, ip, s)
    failed(t + timedelta(seconds=1), ip, s, "guest", "guest")

# C: intruso rapido (3 falhas, entra e executa 3 comandos)
ip, s = "192.0.2.30", sid()
t0 = datetime(2026, 11, 23, 22, 30, 0, 250000)
connect(t0, ip, s)
for i, pw in enumerate(["admin", "1234", "root"]):
    failed(t0 + timedelta(seconds=1 + i * 2), ip, s, "root", pw)
t_ok = t0 + timedelta(seconds=8)
success(t_ok, ip, s, "root", "root")
for j, cmd in enumerate(["cat /etc/passwd", "uname -a", "ls -la /tmp"]):
    command(t_ok + timedelta(seconds=2 + j * 3), ip, s, cmd)

lines.sort(key=lambda item: item[0])
out = Path("data/samples/cowrie.json")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("\n".join(line for _, line in lines) + "\n", encoding="utf-8")
print(f"{len(lines)} linhas geradas em {out}")
