"""
CyberBank: Operation BlackVault
Stage 05 — Digital Crime Scene (Digital Forensics) End-to-End Test Suite

Tests:
     1. Stage 5 is locked (HTTP 403) before Stage 4 is solved
     2. Stage 5 unlocks after Stage 4 completion
     3. Evidence ZIP downloads correctly via HTTP (HTTP 200)
     4. Evidence ZIP extracts successfully and contains all 6 required files
     5. All extracted logs are readable text files
     6. PCAP format is structurally valid (magic number, snaplen, packet headers)
     7. Evidence timestamps correlate across auth, web, app, and PCAP
     8. Intended solution recovers the valid flag
     9. Incorrect flag is rejected
    10. Correct flag is accepted with +200 PTS
    11. Duplicate correct submission returns 409 (no double scoring)
    12. Hint penalties work correctly (progressive -10%, -20%, -30%)
    13. Stage 06 unlocks after Stage 05 completion
    14. Direct URL bypass to Stage 05 without prerequisite is blocked
    15. Evidence package can be regenerated via scripts
    16. No real-world PII or live attack IPs exist in evidence
"""

import os
import re
import struct
import sys
import zipfile
import pytest

# Add platform to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "platform")))

from app import create_app as create_platform_app
from extensions import db
from models import User, Challenge, Submission, Score, Hint
from seed import seed_challenges
from flag_service import verify_flag, hash_flag


EXPECTED_FLAG = "CBANK{FORENSICS_dchen_9f88c2_exf1l_8443}"


# =========================================================================
# Fixtures
# =========================================================================

@pytest.fixture
def platform_app():
    """Create test application for main CTF platform."""
    test_app = create_platform_app("testing")
    with test_app.app_context():
        db.create_all()
        seed_challenges()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def platform_client(platform_app):
    return platform_app.test_client()


@pytest.fixture
def player_user(platform_app):
    """Create an authenticated player on the CTF platform."""
    with platform_app.app_context():
        user = User(
            username="investigator_forensics",
            email="investigator@cyberbank.local",
            role="player",
        )
        user.set_password("Investigator2026!")
        db.session.add(user)
        db.session.commit()
        return user.id


def login_session(client, user_id):
    """Establish authenticated session for given user."""
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True


def solve_stages_up_to(app, user_id, up_to_stage=4):
    """Solve stages 1 through up_to_stage for the player."""
    with app.app_context():
        challenges = Challenge.query.order_by(Challenge.stage_number.asc()).all()
        score_record = Score.query.filter_by(user_id=user_id).first()
        if not score_record:
            score_record = Score(user_id=user_id, total_score=0)
            db.session.add(score_record)

        for chal in challenges:
            if chal.stage_number <= up_to_stage:
                sub = Submission(
                    user_id=user_id,
                    challenge_id=chal.id,
                    success=True,
                    score_awarded=chal.points,
                )
                db.session.add(sub)
                score_record.total_score += chal.points

        db.session.commit()


# =========================================================================
# Tests
# =========================================================================

def test_stage5_locked_before_stage4(platform_app, platform_client, player_user):
    """1. Stage 05 must return 403 Forbidden before Stage 04 is completed."""
    login_session(platform_client, player_user)
    # Solve stages 1-3 only
    solve_stages_up_to(platform_app, player_user, up_to_stage=3)

    resp = platform_client.get(
        "/challenges/stage/5",
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["status"] == "locked"
    assert data["stage_number"] == 5
    assert data["required_stage"] == 4


def test_stage5_unlocks_after_stage4(platform_app, platform_client, player_user):
    """2. Stage 05 unlocks (HTTP 200) after Stage 04 is solved."""
    login_session(platform_client, player_user)
    # Solve stages 1-4
    solve_stages_up_to(platform_app, player_user, up_to_stage=4)

    resp = platform_client.get(
        "/challenges/stage/5",
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["challenge"]["stage_number"] == 5
    assert data["challenge"]["title"] == "Digital Crime Scene"
    assert data["challenge"]["points"] == 200
    assert data["challenge"]["status"] == "available"


def test_stage5_evidence_zip_download(platform_client):
    """3. Evidence ZIP must download with HTTP 200 from static route."""
    resp = platform_client.get("/static/downloads/stage05_evidence.zip")
    assert resp.status_code == 200
    assert len(resp.data) > 1000
    # ZIP magic bytes: PK\x03\x04
    assert resp.data[:4] == b"PK\x03\x04"


def test_stage5_evidence_zip_contents(platform_app):
    """4. Evidence ZIP extracts successfully and contains all 6 required artefacts."""
    zip_path = os.path.join(
        os.path.dirname(__file__), "..", "platform", "static", "downloads", "stage05_evidence.zip"
    )
    assert os.path.exists(zip_path)

    expected_files = {
        "evidence/auth.log",
        "evidence/web_access.log",
        "evidence/application.log",
        "evidence/network_capture.pcap",
        "evidence/suspicious_note.txt",
        "evidence/metadata.txt",
    }

    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = set(zf.namelist())
        assert expected_files.issubset(namelist), f"Missing files in ZIP: {expected_files - namelist}"


def test_stage5_logs_are_readable():
    """5. All extracted logs are readable text files."""
    evidence_dir = os.path.join(os.path.dirname(__file__), "..", "challenges", "stage5_forensics", "evidence")
    text_files = ["auth.log", "web_access.log", "application.log", "suspicious_note.txt", "metadata.txt"]

    for fname in text_files:
        fpath = os.path.join(evidence_dir, fname)
        assert os.path.isfile(fpath), f"Missing evidence file: {fpath}"
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
            assert len(content) > 50, f"Evidence file {fname} is unexpectedly empty"


def test_stage5_pcap_structural_validity():
    """6. PCAP file must parse valid PCAP global and packet headers."""
    pcap_path = os.path.join(
        os.path.dirname(__file__), "..", "challenges", "stage5_forensics", "evidence", "network_capture.pcap"
    )
    assert os.path.exists(pcap_path)

    with open(pcap_path, "rb") as f:
        # Global header: 24 bytes
        global_hdr = f.read(24)
        assert len(global_hdr) == 24
        magic, maj, min_, tz, sig, snaplen, net = struct.unpack("!IHHiIII", global_hdr)
        assert magic == 0xA1B2C3D4  # Standard PCAP Big-Endian Magic
        assert maj == 2 and min_ == 4  # PCAP Version 2.4
        assert snaplen == 65535
        assert net == 1  # Ethernet link layer

        packet_count = 0
        found_flag = False
        while True:
            pkt_hdr = f.read(16)
            if not pkt_hdr:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("!IIII", pkt_hdr)
            assert incl_len <= snaplen
            frame = f.read(incl_len)
            assert len(frame) == incl_len
            packet_count += 1
            if EXPECTED_FLAG.encode("ascii") in frame:
                found_flag = True

        assert packet_count >= 10, f"Expected at least 10 packets, got {packet_count}"
        assert found_flag, "PCAP must contain the exfiltration response with the flag"


def test_stage5_evidence_timestamps_correlate():
    """7. Check that timestamps correlate across auth, web, app, and PCAP."""
    evidence_dir = os.path.join(os.path.dirname(__file__), "..", "challenges", "stage5_forensics", "evidence")

    with open(os.path.join(evidence_dir, "auth.log"), "r") as f:
        auth_data = f.read()
    with open(os.path.join(evidence_dir, "web_access.log"), "r") as f:
        web_data = f.read()
    with open(os.path.join(evidence_dir, "application.log"), "r") as f:
        app_data = f.read()

    # Compromised account 'd.chen' in auth, web, app
    assert "d.chen" in auth_data
    assert "d.chen" in web_data
    assert "d.chen" in app_data

    # Attacker source IP '198.51.100.47' in auth, web, app
    assert "198.51.100.47" in auth_data
    assert "198.51.100.47" in web_data
    assert "198.51.100.47" in app_data

    # Session token in web and app
    assert "sess_9f88c21a44e7" in web_data
    assert "sess_9f88c21a44e7" in app_data

    # Staged archive in web and app
    assert "blackvault_stage05_custody.tar.gz" in web_data
    assert "blackvault_stage05_custody.tar.gz" in app_data


def test_stage5_solution_recovers_flag():
    """8. Extract flag from PCAP and verify against database hash."""
    pcap_path = os.path.join(
        os.path.dirname(__file__), "..", "challenges", "stage5_forensics", "evidence", "network_capture.pcap"
    )
    with open(pcap_path, "rb") as f:
        content = f.read()

    match = re.search(rb"CBANK\{[A-Za-z0-9_-]+\}", content)
    assert match is not None
    recovered_flag = match.group(0).decode("ascii")
    assert recovered_flag == EXPECTED_FLAG

    # Verify against hash_flag
    expected_hash = hash_flag(EXPECTED_FLAG)
    assert verify_flag(recovered_flag, expected_hash)


def test_stage5_incorrect_flag_rejected(platform_app, platform_client, player_user):
    """9. Incorrect flag submissions must be rejected."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=4)

    with platform_app.app_context():
        c5 = Challenge.query.filter_by(stage_number=5).first()

    resp = platform_client.post(
        f"/challenges/{c5.id}/submit",
        data={"flag": "CBANK{FORENSICS_WRONG_FLAG_0000}"},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["status"] == "incorrect"
    assert "Incorrect flag" in data["message"]


def test_stage5_correct_flag_awarded(platform_app, platform_client, player_user):
    """10. Correct flag submission awards +200 PTS."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=4)

    with platform_app.app_context():
        c5 = Challenge.query.filter_by(stage_number=5).first()

    resp = platform_client.post(
        f"/challenges/{c5.id}/submit",
        data={"flag": EXPECTED_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["points_awarded"] == 200
    # Stages 1-4 total 500 PTS (50+100+200+150), so total is now 700 PTS
    assert data["new_total_score"] == 700


def test_stage5_duplicate_solve_prevented(platform_app, platform_client, player_user):
    """11. Submitting the flag a second time returns 409 Conflict."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=4)

    with platform_app.app_context():
        c5 = Challenge.query.filter_by(stage_number=5).first()

    # First solve
    resp1 = platform_client.post(
        f"/challenges/{c5.id}/submit",
        data={"flag": EXPECTED_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp1.status_code == 200

    # Second solve attempt
    resp2 = platform_client.post(
        f"/challenges/{c5.id}/submit",
        data={"flag": EXPECTED_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp2.status_code == 409
    data = resp2.get_json()
    assert data["status"] == "duplicate"


def test_stage5_hint_penalties(platform_app, platform_client, player_user):
    """12. Hint unlocks apply progressive penalties (-10%, -20%, -30%)."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=4)

    with platform_app.app_context():
        c5 = Challenge.query.filter_by(stage_number=5).first()
        hints = Hint.query.filter_by(challenge_id=c5.id).order_by(Hint.hint_number.asc()).all()
        assert len(hints) == 3
        assert hints[0].penalty_percentage == 10
        assert hints[1].penalty_percentage == 20
        assert hints[2].penalty_percentage == 30

    # Unlock Hint 1
    resp_h1 = platform_client.post(
        f"/challenges/{c5.id}/hints/1/unlock",
        headers={"Accept": "application/json"},
    )
    assert resp_h1.status_code == 200
    assert resp_h1.get_json()["status"] == "success"

    # Unlock Hint 2
    resp_h2 = platform_client.post(
        f"/challenges/{c5.id}/hints/2/unlock",
        headers={"Accept": "application/json"},
    )
    assert resp_h2.status_code == 200

    # Solve with hints 1 and 2 unlocked (-10% + -20% = -30% penalty)
    # Base: 200 * 0.70 = 140 pts
    resp_sub = platform_client.post(
        f"/challenges/{c5.id}/submit",
        data={"flag": EXPECTED_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp_sub.status_code == 200
    assert resp_sub.get_json()["points_awarded"] == 140


def test_stage6_unlocks_after_stage5(platform_app, platform_client, player_user):
    """13. Stage 06 unlocks after Stage 05 is completed."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=4)

    with platform_app.app_context():
        c5 = Challenge.query.filter_by(stage_number=5).first()

    # Stage 6 is locked before Stage 5 solve
    resp_before = platform_client.get(
        "/challenges/stage/6",
        headers={"Accept": "application/json"},
    )
    assert resp_before.status_code == 403

    # Solve Stage 5
    platform_client.post(
        f"/challenges/{c5.id}/submit",
        data={"flag": EXPECTED_FLAG},
        headers={"Accept": "application/json"},
    )

    # Stage 6 is now available
    resp_after = platform_client.get(
        "/challenges/stage/6",
        headers={"Accept": "application/json"},
    )
    assert resp_after.status_code == 200
    assert resp_after.get_json()["challenge"]["status"] == "available"


def test_stage5_direct_url_bypass_blocked(platform_app, platform_client, player_user):
    """14. Direct URL navigation to Stage 05 when locked redirects or returns 403."""
    login_session(platform_client, player_user)
    # No stages solved

    # JSON request -> 403
    resp_json = platform_client.get(
        "/challenges/stage/5",
        headers={"Accept": "application/json"},
    )
    assert resp_json.status_code == 403

    # Browser GET -> redirect to dashboard
    resp_html = platform_client.get("/challenges/stage/5")
    assert resp_html.status_code == 302
    assert "/dashboard" in resp_html.headers["Location"]


def test_stage5_regeneration_script():
    """15. Evidence package can be regenerated cleanly via script."""
    import subprocess
    cmd = [sys.executable, "scripts/generate_stage05_evidence.py"]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    assert res.returncode == 0
    assert "[+] Stage 05 Evidence Package ready" in res.stdout


def test_stage5_no_real_pii_or_live_ips():
    """16. Ensure only fictional and RFC 5737 test IP ranges are used."""
    evidence_dir = os.path.join(os.path.dirname(__file__), "..", "challenges", "stage5_forensics", "evidence")
    text_files = ["auth.log", "web_access.log", "application.log", "suspicious_note.txt", "metadata.txt"]

    # Fictional / private / test IPs allowed:
    # 198.51.100.x (RFC 5737 TEST-NET-2)
    # 203.0.113.x (RFC 5737 TEST-NET-3)
    # 10.x.x.x (RFC 1918 Private)
    # 127.0.0.1 (Loopback)
    for fname in text_files:
        fpath = os.path.join(evidence_dir, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
            # Extract all IPv4 patterns
            ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content))
            for ip in ips:
                assert (
                    ip.startswith("10.")
                    or ip.startswith("198.51.100.")
                    or ip.startswith("203.0.113.")
                    or ip.startswith("192.0.2.")
                    or ip.startswith("127.")
                ), f"Unexpected non-test IP address found in {fname}: {ip}"
