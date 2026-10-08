"""
CyberBank: Operation BlackVault
Stage 4 — The Banker's Secret Code (Cryptography) End-to-End Test Suite

Tests:
    1. Stage 4 is locked (HTTP 403) until Stages 1-3 are solved
    2. Stage 4 unlocks after Stage 3 completion
    3. Evidence file downloads correctly and contains hex data
    4. Challenge is solvable (hex decode → ROT13 → flag recovered)
    5. Incorrect flag rejected
    6. Correct flag accepted with +150 PTS
    7. Duplicate correct submission returns 409 (no additional points)
    8. Hint penalties work correctly
    9. Stage 5 unlocks after Stage 4 completion
   10. Direct URL bypass prevented
   11. Flag not exposed in frontend HTML source
   12. Evidence artefact can be regenerated
"""

import codecs
import os
import sys

import pytest

# Add platform to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "platform")))

from app import create_app as create_platform_app
from extensions import db
from models import User, Challenge, Submission, Score, Log
from seed import seed_challenges
from flag_service import verify_flag


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
            username="crypto_analyst",
            email="analyst@blackvault.local",
            role="player",
        )
        user.set_password("CryptoPass2026!")
        db.session.add(user)
        db.session.commit()
        return user.id


def login_user(client, username="crypto_analyst", password="CryptoPass2026!"):
    return client.post("/login", json={"identifier": username, "password": password})


def solve_stages_1_to_3(client):
    """Solve prerequisite Stages 1-3 to unlock Stage 4."""
    client.post("/challenges/1/submit", json={"flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"})
    client.post("/challenges/2/submit", json={"flag": "CBANK{STEGO_h1dd3n_sp3ctrum_4491}"})
    client.post("/challenges/3/submit", json={"flag": "CBANK{WEB_sqli_byp4ss_v4ult_7721}"})


STAGE4_FLAG = "CBANK{CRYPTO_b4nk3r_c1ph3r_br34k_3310}"


# =========================================================================
# 1. Stage Locking Tests
# =========================================================================

def test_stage4_locked_before_stage3_completion(platform_client, player_user):
    """Direct access to Stage 4 must be rejected (HTTP 403) before Stage 3 is solved."""
    login_user(platform_client)

    # Stage 4 is locked initially
    resp = platform_client.get("/challenges/4", headers={"Accept": "application/json"})
    assert resp.status_code == 403

    # Solve Stage 1 only → Stage 4 remains locked
    platform_client.post("/challenges/1/submit", json={"flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"})
    resp_after_s1 = platform_client.get("/challenges/4", headers={"Accept": "application/json"})
    assert resp_after_s1.status_code == 403

    # Solve Stage 2 → Stage 4 still locked (Stage 3 not solved)
    platform_client.post("/challenges/2/submit", json={"flag": "CBANK{STEGO_h1dd3n_sp3ctrum_4491}"})
    resp_after_s2 = platform_client.get("/challenges/4", headers={"Accept": "application/json"})
    assert resp_after_s2.status_code == 403


def test_stage4_locked_submit_rejected(platform_client, player_user):
    """Submitting a flag for locked Stage 4 is rejected with HTTP 403."""
    login_user(platform_client)
    resp = platform_client.post(
        "/challenges/4/submit",
        json={"flag": STAGE4_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 403
    assert resp.get_json()["status"] == "locked"


# =========================================================================
# 2. Stage Unlocking Tests
# =========================================================================

def test_stage4_unlocked_after_stage3(platform_client, player_user):
    """Stage 4 becomes available after solving Stages 1-3."""
    login_user(platform_client)
    solve_stages_1_to_3(platform_client)

    resp = platform_client.get("/challenges/4", headers={"Accept": "application/json"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["challenge"]["title"] == "The Banker's Secret Code"
    assert data["challenge"]["status"] == "available"
    assert data["challenge"]["domain"] == "crypto"
    assert data["challenge"]["points"] == 150


def test_stage4_html_view_has_evidence_section(platform_client, player_user):
    """Stage 4 HTML view includes the download section for the evidence file."""
    login_user(platform_client)
    solve_stages_1_to_3(platform_client)

    resp = platform_client.get("/challenges/4")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "STAGE04_BANKER_MESSAGE.TXT" in html
    assert "Download Intercept" in html
    assert "CyberChef" in html
    assert "Cryptographic Intercept Analysis" in html
    # Flag must NOT appear in HTML source
    assert STAGE4_FLAG not in html


# =========================================================================
# 3. Evidence File Tests
# =========================================================================

def test_evidence_file_exists():
    """Verify stage04_banker_message.txt exists in the static downloads directory."""
    evidence_path = os.path.join(
        os.path.dirname(__file__), "..", "platform", "static", "downloads",
        "stage04_banker_message.txt"
    )
    assert os.path.isfile(evidence_path), "Evidence file stage04_banker_message.txt not found"


def test_evidence_file_contains_hex_data():
    """Verify the evidence file contains valid hex-encoded data (not plaintext)."""
    evidence_path = os.path.join(
        os.path.dirname(__file__), "..", "platform", "static", "downloads",
        "stage04_banker_message.txt"
    )
    with open(evidence_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    hex_lines = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    assert len(hex_lines) > 0, "No hex data lines found in evidence file"

    # All non-comment content should be valid hex characters
    hex_data = "".join(hex_lines)
    assert all(c in "0123456789abcdef" for c in hex_data), "Evidence contains non-hex characters"

    # The plaintext flag must NOT appear directly in the file
    raw_content = "".join(lines)
    assert STAGE4_FLAG not in raw_content, "Plaintext flag exposed in evidence file!"


def test_evidence_file_is_solvable():
    """Decode the evidence file (hex → ROT13) and verify the flag is recovered."""
    evidence_path = os.path.join(
        os.path.dirname(__file__), "..", "platform", "static", "downloads",
        "stage04_banker_message.txt"
    )
    with open(evidence_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    hex_data = "".join(
        line.strip() for line in lines if line.strip() and not line.startswith("#")
    )

    # Step 1: Hex decode
    decoded_bytes = bytes.fromhex(hex_data).decode("utf-8")

    # Step 2: ROT13
    plaintext = codecs.decode(decoded_bytes, "rot_13")

    assert STAGE4_FLAG in plaintext, "Flag not found after hex + ROT13 decoding"


def test_evidence_file_downloadable(platform_client, player_user):
    """Evidence file should be downloadable via the static file route."""
    login_user(platform_client)
    resp = platform_client.get("/static/downloads/stage04_banker_message.txt")
    assert resp.status_code == 200
    content = resp.get_data(as_text=True)
    assert "CB-IR-2026-0447" in content  # Header comment from generated file
    assert STAGE4_FLAG not in content  # Plaintext flag not in raw file


# =========================================================================
# 4. Flag Validation Tests
# =========================================================================

def test_stage4_flag_hash_matches(platform_app):
    """Verify the stored flag hash in the database matches the expected flag."""
    with platform_app.app_context():
        challenge = Challenge.query.filter_by(stage_number=4).first()
        assert challenge is not None
        assert verify_flag(STAGE4_FLAG, challenge.flag_hash) is True


def test_stage4_incorrect_flag_rejected(platform_client, player_user):
    """Submitting an incorrect flag returns an error."""
    login_user(platform_client)
    solve_stages_1_to_3(platform_client)

    resp = platform_client.post(
        "/challenges/4/submit",
        json={"flag": "CBANK{WRONG_FLAG_12345}"},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 400
    assert resp.get_json()["status"] == "incorrect"


def test_stage4_correct_flag_accepted(platform_client, player_user, platform_app):
    """Submitting the correct flag awards +150 PTS."""
    login_user(platform_client)
    solve_stages_1_to_3(platform_client)

    resp = platform_client.post(
        "/challenges/4/submit",
        json={"flag": STAGE4_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["points_awarded"] == 150
    # Total: 100 (S1) + 100 (S2) + 150 (S3) + 150 (S4) = 500
    assert data["new_total_score"] == 500


def test_stage4_duplicate_submission_rejected(platform_client, player_user):
    """Submitting the correct flag a second time returns 409 with no additional points."""
    login_user(platform_client)
    solve_stages_1_to_3(platform_client)

    # First submission — success
    resp1 = platform_client.post(
        "/challenges/4/submit",
        json={"flag": STAGE4_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp1.status_code == 200

    # Second submission — duplicate
    resp2 = platform_client.post(
        "/challenges/4/submit",
        json={"flag": STAGE4_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp2.status_code == 409
    assert resp2.get_json()["status"] == "duplicate"
    assert resp2.get_json()["already_solved"] is True


# =========================================================================
# 5. Hint Penalty Tests
# =========================================================================

def test_stage4_hint_penalties(platform_client, player_user, platform_app):
    """Using all 3 hints applies cumulative 60% penalty (150 → 60 pts)."""
    login_user(platform_client)
    solve_stages_1_to_3(platform_client)

    # Unlock all 3 hints sequentially
    for hint_num in [1, 2, 3]:
        hint_resp = platform_client.post(
            f"/challenges/4/hints/{hint_num}/unlock",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        assert hint_resp.status_code == 200

    # Verify hints are unlocked
    hints_resp = platform_client.get(
        "/challenges/4/hints",
        headers={"Accept": "application/json"},
    )
    assert hints_resp.status_code == 200
    hints_data = hints_resp.get_json()["hints"]
    assert all(h["is_unlocked"] for h in hints_data)

    # Submit correct flag — points should reflect penalty
    resp = platform_client.post(
        "/challenges/4/submit",
        json={"flag": STAGE4_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    # 150 base - 10% - 20% - 30% = 150 - 15 - 30 - 45 = 60
    assert data["points_awarded"] == 60


# =========================================================================
# 6. Stage Progression Tests
# =========================================================================

def test_stage5_unlocks_after_stage4(platform_client, player_user):
    """Stage 5 (Digital Crime Scene) becomes available after solving Stage 4."""
    login_user(platform_client)
    solve_stages_1_to_3(platform_client)

    # Stage 5 is locked before Stage 4 solve
    s5_before = platform_client.get("/challenges/5", headers={"Accept": "application/json"})
    assert s5_before.status_code == 403

    # Solve Stage 4
    platform_client.post(
        "/challenges/4/submit",
        json={"flag": STAGE4_FLAG},
        headers={"Accept": "application/json"},
    )

    # Stage 5 is now available
    s5_after = platform_client.get("/challenges/5", headers={"Accept": "application/json"})
    assert s5_after.status_code == 200
    assert s5_after.get_json()["challenge"]["title"] == "Digital Crime Scene"
    assert s5_after.get_json()["challenge"]["status"] == "available"


def test_stage4_completed_status_after_solve(platform_client, player_user):
    """After solving Stage 4, its status shows as 'completed'."""
    login_user(platform_client)
    solve_stages_1_to_3(platform_client)

    platform_client.post(
        "/challenges/4/submit",
        json={"flag": STAGE4_FLAG},
        headers={"Accept": "application/json"},
    )

    resp = platform_client.get("/challenges/4", headers={"Accept": "application/json"})
    assert resp.status_code == 200
    assert resp.get_json()["challenge"]["status"] == "completed"


# =========================================================================
# 7. Artefact Regeneration Test
# =========================================================================

def test_build_script_reproduces_artefact():
    """Running build_stage04_challenge.py produces a valid, solvable evidence file."""
    import importlib.util

    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "scripts", "build_stage04_challenge.py")
    )
    assert os.path.isfile(script_path), "build_stage04_challenge.py script not found"

    spec = importlib.util.spec_from_file_location("gen_stage04", script_path)
    gen_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen_module)

    # Test the encoding functions
    test_text = "Hello, CyberBank!"
    rot13d = gen_module.apply_rot13(test_text)
    assert rot13d == "Uryyb, PloreOnax!"

    hex_encoded = gen_module.apply_hex_encode(rot13d)
    # Reverse it
    decoded = bytes.fromhex(hex_encoded).decode("utf-8")
    recovered = codecs.decode(decoded, "rot_13")
    assert recovered == test_text
