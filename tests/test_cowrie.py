from datetime import datetime
from pathlib import Path

import pytest

from armadillo_sentinel.cowrie import parse_cowrie_line
from armadillo_sentinel.parser import parse_file

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "cowrie.json"

FAILED = '{"eventid":"cowrie.login.failed","username":"root","password":"123456","message":"login attempt [root/123456] failed","sensor":"honeypot","timestamp":"2026-11-24T03:10:01.123456Z","src_ip":"192.0.2.10","session":"a1b2c3d4e5f6"}'
SUCCESS = '{"eventid":"cowrie.login.success","username":"root","password":"toor","message":"login attempt [root/toor] succeeded","sensor":"honeypot","timestamp":"2026-11-24T03:13:21.123456Z","src_ip":"192.0.2.10","session":"a1b2c3d4e5f6"}'
COMMAND = '{"eventid":"cowrie.command.input","input":"uname -a","message":"CMD: uname -a","sensor":"honeypot","timestamp":"2026-11-24T03:13:24.123456Z","src_ip":"192.0.2.10","session":"a1b2c3d4e5f6"}'
CONNECT = '{"eventid":"cowrie.session.connect","src_port":51000,"dst_port":2222,"message":"New connection","sensor":"honeypot","timestamp":"2026-11-24T03:10:00.123456Z","src_ip":"192.0.2.10","session":"a1b2c3d4e5f6"}'


def test_login_failed():
    ev = parse_cowrie_line(FAILED)
    assert ev["event_type"] == "login_failed"
    assert ev["source_ip"] == "192.0.2.10"
    assert ev["username"] == "root"
    assert ev["service"] == "cowrie"
    assert ev["source"] == "cowrie"
    assert ev["event_time"] == datetime(2026, 11, 24, 3, 10, 1, 123456)
    assert ev["raw_line"] == FAILED


def test_login_success_is_stored_as_honeypot_login():
    assert parse_cowrie_line(SUCCESS)["event_type"] == "honeypot_login"


def test_command_input():
    ev = parse_cowrie_line(COMMAND)
    assert ev["event_type"] == "command"
    assert ev["username"] is None
    assert ev["source_ip"] == "192.0.2.10"


def test_timestamp_with_offset_is_converted_to_utc():
    line = FAILED.replace("2026-11-24T03:10:01.123456Z", "2026-11-24T00:10:01.000000-03:00")
    assert parse_cowrie_line(line)["event_time"] == datetime(2026, 11, 24, 3, 10, 1)


@pytest.mark.parametrize(
    "line",
    [
        CONNECT,
        "",
        "{ json quebrado",
        "Nov 21 03:10:00 srv01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
        FAILED.replace('"src_ip":"192.0.2.10",', ""),
        FAILED.replace("2026-11-24T03:10:01.123456Z", "ontem"),
    ],
)
def test_unusable_lines_are_ignored(line):
    assert parse_cowrie_line(line) is None


def test_parse_file_detects_cowrie_format(tmp_path):
    f = tmp_path / "cowrie.json"
    f.write_text("\n" + "\n".join([FAILED, CONNECT, COMMAND]) + "\n", encoding="utf-8")
    events = parse_file(f)
    assert [e["event_type"] for e in events] == ["login_failed", "command"]


@pytest.mark.skipif(not SAMPLE.exists(), reason="log de exemplo do Cowrie ausente")
def test_sample_file_counts():
    kinds = [e["event_type"] for e in parse_file(SAMPLE)]
    assert len(kinds) == 64
    assert kinds.count("login_failed") == 55
    assert kinds.count("honeypot_login") == 2
    assert kinds.count("command") == 7
