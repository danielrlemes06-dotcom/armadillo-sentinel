from datetime import datetime
from pathlib import Path

import pytest

from armadillo_sentinel.parser import parse_file, parse_line

YEAR = 2026
SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "auth.log"

FAILED = "Nov 21 03:10:00 srv01 sshd[2211]: Failed password for root from 203.0.113.50 port 51122 ssh2"
FAILED_INVALID = "Nov 21 03:10:04 srv01 sshd[2212]: Failed password for invalid user admin from 203.0.113.50 port 51123 ssh2"
ACCEPTED = "Nov 22 09:15:02 srv01 sshd[2301]: Accepted password for daniel from 198.51.100.10 port 40022 ssh2"


def test_failed_password():
    ev = parse_line(FAILED, YEAR)
    assert ev["event_type"] == "login_failed"
    assert ev["source_ip"] == "203.0.113.50"
    assert ev["username"] == "root"
    assert ev["service"] == "sshd"
    assert ev["event_time"] == datetime(2026, 11, 21, 3, 10, 0)
    assert ev["source"] == "auth.log"
    assert ev["raw_line"] == FAILED


def test_failed_password_invalid_user_keeps_real_username():
    ev = parse_line(FAILED_INVALID, YEAR)
    assert ev["event_type"] == "login_failed"
    assert ev["username"] == "admin"


def test_accepted_password():
    ev = parse_line(ACCEPTED, YEAR)
    assert ev["event_type"] == "login_success"
    assert ev["username"] == "daniel"
    assert ev["source_ip"] == "198.51.100.10"


def test_accepted_publickey():
    line = "Nov 22 09:20:00 srv01 sshd[2302]: Accepted publickey for deploy from 198.51.100.20 port 22 ssh2"
    assert parse_line(line, YEAR)["event_type"] == "login_success"


def test_invalid_user_line():
    line = "Nov 22 10:00:00 srv01 sshd[2303]: Invalid user oracle from 203.0.113.9 port 4444"
    ev = parse_line(line, YEAR)
    assert ev["event_type"] == "invalid_user"
    assert ev["username"] == "oracle"
    assert ev["source_ip"] == "203.0.113.9"


def test_day_padded_with_space():
    line = "Nov  2 08:00:01 srv01 sshd[1]: Accepted password for maria from 198.51.100.11 port 1 ssh2"
    assert parse_line(line, YEAR)["event_time"] == datetime(2026, 11, 2, 8, 0, 1)


def test_ipv6_address():
    line = "Nov 22 11:00:00 srv01 sshd[5]: Failed password for root from 2001:db8::1 port 22 ssh2"
    assert parse_line(line, YEAR)["source_ip"] == "2001:db8::1"


def test_year_is_applied():
    assert parse_line(FAILED, 2025)["event_time"].year == 2025


def test_line_ending_is_removed_from_raw_line():
    assert parse_line(ACCEPTED + "\r\n", YEAR)["raw_line"] == ACCEPTED


@pytest.mark.parametrize(
    "line",
    [
        "Nov 21 03:10:00 srv01 sshd[1]: Connection closed by 203.0.113.50 port 1",
        "linha qualquer sem formato de syslog",
        "",
    ],
)
def test_unrecognized_lines_are_ignored(line):
    assert parse_line(line, YEAR) is None


def test_parse_file_skips_noise(tmp_path):
    f = tmp_path / "x.log"
    f.write_text("\n".join([FAILED, "lixo qualquer", ACCEPTED]) + "\n", encoding="utf-8")
    events = parse_file(f, year=YEAR)
    assert [e["event_type"] for e in events] == ["login_failed", "login_success"]


@pytest.mark.skipif(not SAMPLE.exists(), reason="log de exemplo ausente")
def test_sample_file_counts():
    events = parse_file(SAMPLE, year=YEAR)
    kinds = [e["event_type"] for e in events]
    assert len(events) == 175
    assert kinds.count("login_failed") == 99
    assert kinds.count("login_success") == 76
