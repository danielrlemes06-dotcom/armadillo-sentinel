import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
HOST = "srv01"
events = []


def add(ts, msg):
    pid = random.randint(1000, 9999)
    line = f"{ts.strftime('%b %d %H:%M:%S')} {HOST} sshd[{pid}]: {msg}"
    events.append((ts, line))


def port():
    return random.randint(30000, 60000)


base = datetime(2026, 11, 20)
users = ["daniel", "maria", "joao"]
good_ips = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]

# trafego normal em horario comercial, com alguns erros de senha
for day in range(3):
    for _ in range(25):
        ts = base + timedelta(
            days=day,
            hours=random.randint(8, 17),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )
        u, ip = random.choice(users), random.choice(good_ips)
        if random.random() < 0.1:
            add(ts, f"Failed password for {u} from {ip} port {port()} ssh2")
        add(ts + timedelta(seconds=5), f"Accepted password for {u} from {ip} port {port()} ssh2")

# ataque de forca bruta: 80 tentativas em ~5 minutos
attacker = "203.0.113.50"
start = base + timedelta(days=1, hours=3, minutes=10)
for i in range(80):
    u = random.choice(["root", "admin", "ubuntu", "test", "oracle"])
    prefix = "" if u == "root" else "invalid user "
    add(start + timedelta(seconds=i * 4),
        f"Failed password for {prefix}{u} from {attacker} port {port()} ssh2")

# scanner lento: 12 tentativas espalhadas em 2 horas
slow = "203.0.113.77"
for i in range(12):
    add(base + timedelta(days=2, hours=14, minutes=i * 10),
        f"Failed password for invalid user guest from {slow} port {port()} ssh2")

# login bem-sucedido de madrugada
add(base + timedelta(days=2, hours=2, minutes=41),
    "Accepted password for maria from 198.51.100.99 port 52000 ssh2")

events.sort(key=lambda e: e[0])
out = Path("data/samples/auth.log")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("\n".join(line for _, line in events) + "\n", encoding="utf-8")
print(f"{len(events)} linhas geradas em {out}")
