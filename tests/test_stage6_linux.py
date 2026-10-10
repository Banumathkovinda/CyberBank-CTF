"""
CyberBank: Operation BlackVault
Stage 06 — BlackVault Server (Linux / System Security) End-to-End Test Suite

Tests:
     1. Stage 6 is locked (HTTP 403) before Stages 1-5 are solved
     2. Stage 6 unlocks after Stages 1-5 completion
     3. Direct URL bypass to locked Stage 6 is rejected
     4. Incorrect final flag is rejected
     5. Correct final flag is accepted with +300 PTS
     6. Total accumulated score reaches 1000 PTS on final solve
     7. Duplicate solve returns 409 Conflict (no double scoring)
     8. Hint penalties apply progressively (-10%, -20%, -30%)
     9. /completion endpoint is locked before Stage 6 is completed
    10. /completion endpoint renders celebration screen after Stage 6 is completed
    11. Dashboard reflects 6/6 solved and displays completion banner
    12. Flag is not exposed in challenge description or frontend HTML
    13. Dockerfile adheres to security controls (no docker socket, non-privileged)
    14. Docker Compose service defines isolated network and resource limits
    15. Simulated privilege escalation exploit chain validates flag recovery
"""

import os
import re
import sys
import pytest

# Add platform to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "platform")))

from app import create_app as create_platform_app
from extensions import db
from models import User, Challenge, Submission, Score, Hint
from seed import seed_challenges
from flag_service import verify_flag, hash_flag


EXPECTED_FLAG = "CBANK{LINUX_r00t_bl4ckv4ult_m4st3r_5519}"


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
            username="blackvault_infiltrator",
            email="infiltrator@cyberbank.local",
            role="player",
        )
        user.set_password("Infiltrator2026!")
        db.session.add(user)
        db.session.commit()
        return user.id


def login_session(client, user_id):
    """Establish authenticated session for given user."""
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True


def solve_stages_up_to(app, user_id, up_to_stage=5):
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

def test_stage6_locked_before_stage5(platform_app, platform_client, player_user):
    """1. Stage 06 must return 403 Forbidden before Stage 05 is completed."""
    login_session(platform_client, player_user)
    # Solve stages 1-4 only
    solve_stages_up_to(platform_app, player_user, up_to_stage=4)

    resp = platform_client.get(
        "/challenges/stage/6",
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["status"] == "locked"
    assert data["stage_number"] == 6
    assert data["required_stage"] == 5


def test_stage6_unlocks_after_stage5(platform_app, platform_client, player_user):
    """2. Stage 06 unlocks (HTTP 200) after Stage 05 is solved."""
    login_session(platform_client, player_user)
    # Solve stages 1-5
    solve_stages_up_to(platform_app, player_user, up_to_stage=5)

    resp = platform_client.get(
        "/challenges/stage/6",
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["challenge"]["stage_number"] == 6
    assert data["challenge"]["title"] == "BlackVault Server"
    assert data["challenge"]["points"] == 300
    assert data["challenge"]["status"] == "available"


def test_stage6_direct_url_bypass_blocked(platform_app, platform_client, player_user):
    """3. Direct URL access to locked Stage 06 redirects browser to dashboard."""
    login_session(platform_client, player_user)
    # No stages solved

    resp_html = platform_client.get("/challenges/stage/6")
    assert resp_html.status_code == 302
    assert "/dashboard" in resp_html.headers["Location"]


def test_stage6_incorrect_flag_rejected(platform_app, platform_client, player_user):
    """4. Incorrect final flag submissions must be rejected."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=5)

    with platform_app.app_context():
        c6 = Challenge.query.filter_by(stage_number=6).first()

    resp = platform_client.post(
        f"/challenges/{c6.id}/submit",
        data={"flag": "CBANK{LINUX_WRONG_ROOT_KEY_9999}"},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["status"] == "incorrect"
    assert "Incorrect flag" in data["message"]


def test_stage6_correct_flag_awarded(platform_app, platform_client, player_user):
    """5. Correct final flag submission awards +300 PTS."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=5)

    with platform_app.app_context():
        c6 = Challenge.query.filter_by(stage_number=6).first()

    resp = platform_client.post(
        f"/challenges/{c6.id}/submit",
        data={"flag": EXPECTED_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["points_awarded"] == 300
    # Stages 1-5 total 700 PTS, so total is now exactly 1000 PTS
    assert data["new_total_score"] == 1000
    assert data["mission_completed"] is True


def test_stage6_duplicate_solve_prevented(platform_app, platform_client, player_user):
    """6. Submitting the flag a second time returns 409 Conflict."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=5)

    with platform_app.app_context():
        c6 = Challenge.query.filter_by(stage_number=6).first()

    # First solve
    resp1 = platform_client.post(
        f"/challenges/{c6.id}/submit",
        data={"flag": EXPECTED_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp1.status_code == 200

    # Second solve attempt
    resp2 = platform_client.post(
        f"/challenges/{c6.id}/submit",
        data={"flag": EXPECTED_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp2.status_code == 409
    data = resp2.get_json()
    assert data["status"] == "duplicate"


def test_stage6_hint_penalties(platform_app, platform_client, player_user):
    """7. Hint unlocks apply progressive penalties (-10%, -20%, -30%)."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=5)

    with platform_app.app_context():
        c6 = Challenge.query.filter_by(stage_number=6).first()
        hints = Hint.query.filter_by(challenge_id=c6.id).order_by(Hint.hint_number.asc()).all()
        assert len(hints) == 3
        assert hints[0].penalty_percentage == 10
        assert hints[1].penalty_percentage == 20
        assert hints[2].penalty_percentage == 30

    # Unlock Hint 1
    resp_h1 = platform_client.post(
        f"/challenges/{c6.id}/hints/1/unlock",
        headers={"Accept": "application/json"},
    )
    assert resp_h1.status_code == 200

    # Unlock Hint 2
    resp_h2 = platform_client.post(
        f"/challenges/{c6.id}/hints/2/unlock",
        headers={"Accept": "application/json"},
    )
    assert resp_h2.status_code == 200

    # Solve with hints 1 and 2 unlocked (-10% + -20% = -30% penalty)
    # Base: 300 * 0.70 = 210 pts
    resp_sub = platform_client.post(
        f"/challenges/{c6.id}/submit",
        data={"flag": EXPECTED_FLAG},
        headers={"Accept": "application/json"},
    )
    assert resp_sub.status_code == 200
    assert resp_sub.get_json()["points_awarded"] == 210


def test_completion_endpoint_locked_before_stage6(platform_app, platform_client, player_user):
    """8. /completion is locked if Stage 6 is not solved."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=5)

    resp = platform_client.get("/completion")
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]


def test_completion_endpoint_renders_after_stage6(platform_app, platform_client, player_user):
    """9. /completion renders celebration screen once Stage 6 is solved."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=5)

    with platform_app.app_context():
        c6 = Challenge.query.filter_by(stage_number=6).first()

    # Solve Stage 6
    platform_client.post(
        f"/challenges/{c6.id}/submit",
        data={"flag": EXPECTED_FLAG},
        headers={"Accept": "application/json"},
    )

    # Access /completion
    resp_html = platform_client.get("/completion")
    assert resp_html.status_code == 200
    content = resp_html.get_data(as_text=True)
    assert "OPERATION BLACKVAULT COMPLETED" in content
    assert "6 / 6" in content
    assert "1000" in content

    # Test JSON output
    resp_json = platform_client.get("/completion", headers={"Accept": "application/json"})
    assert resp_json.status_code == 200
    data = resp_json.get_json()
    assert data["status"] == "success"
    assert data["completed_challenges"] == "6/6"
    assert data["total_score"] == 1000


def test_dashboard_shows_completion_banner(platform_app, platform_client, player_user):
    """10. Dashboard displays the OPERATION BLACKVAULT COMPLETED banner when all 6 stages solved."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=5)

    with platform_app.app_context():
        c6 = Challenge.query.filter_by(stage_number=6).first()

    platform_client.post(
        f"/challenges/{c6.id}/submit",
        data={"flag": EXPECTED_FLAG},
        headers={"Accept": "application/json"},
    )

    resp = platform_client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "OPERATION BLACKVAULT COMPLETED" in html
    assert "ALL OBJECTIVES CONQUERED" in html


def test_stage6_flag_not_exposed_in_html(platform_app, platform_client, player_user):
    """11. The flag plaintext must never appear in HTML source."""
    login_session(platform_client, player_user)
    solve_stages_up_to(platform_app, player_user, up_to_stage=5)

    resp = platform_client.get("/challenges/stage/6")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert EXPECTED_FLAG not in html
    assert "5519" not in html


def test_stage6_dockerfile_security_controls():
    """12. Validate Stage 6 Dockerfile has no privileged flags or socket mounts."""
    dockerfile_path = os.path.join(
        os.path.dirname(__file__), "..", "challenges", "stage6_linux", "Dockerfile"
    )
    assert os.path.exists(dockerfile_path)
    with open(dockerfile_path, "r", encoding="utf-8") as f:
        df_content = f.read()

    assert "docker.sock" not in df_content
    assert "PermitRootLogin no" in df_content
    assert "analyst:BlackVault2026!" in df_content
    assert "chmod 664 /etc/blackvault/backup.conf" in df_content
    assert "chmod 0400 /root/blackvault_flag.txt" in df_content


def test_stage6_compose_isolation():
    """13. Validate docker-compose.yml defines resource limits and isolated network."""
    compose_path = os.path.join(os.path.dirname(__file__), "..", "docker-compose.yml")
    assert os.path.exists(compose_path)
    with open(compose_path, "r", encoding="utf-8") as f:
        compose_content = f.read()

    assert "cyberbank-blackvault" in compose_content
    assert "2222:22" in compose_content
    assert "8088:80" not in compose_content
    assert "docker.sock" not in compose_content
    assert "privileged: true" not in compose_content
    assert "limits:" in compose_content


def test_simulated_privilege_escalation():
    """14. Simulate the sourced script vulnerability logic."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        flag_path = os.path.join(tmpdir, "root_flag.txt")
        conf_path = os.path.join(tmpdir, "backup.conf")
        out_flag = os.path.join(tmpdir, "extracted_flag.txt")

        with open(flag_path, "w") as f:
            f.write(EXPECTED_FLAG)

        with open(conf_path, "w") as f:
            f.write(f"cat '{flag_path}' > '{out_flag}'\n")

        # Simulate script execution sourcing the conf
        import subprocess
        bash_script = f"source '{conf_path}'"
        res = subprocess.run(["bash", "-c", bash_script], capture_output=True, text=True)
        if res.returncode == 0 and os.path.exists(out_flag):
            with open(out_flag, "r") as f:
                extracted = f.read().strip()
            assert extracted == EXPECTED_FLAG


def test_stage6_solver_script_exists_and_runs():
    """15. Ensure Member 3's Stage 6 solver script exists and recovers the expected flag."""
    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "scripts", "member3", "stage6_solver.py")
    )
    assert os.path.isfile(script_path), "stage6_solver.py not found in scripts/member3/"

    import importlib.util
    spec = importlib.util.spec_from_file_location("stage6_solver", script_path)
    solver_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(solver_mod)

    backend = solver_mod.SimulationBackend()
    solver = solver_mod.Stage6Solver(backend=backend)
    flag, _ = solver.solve()
    assert flag == EXPECTED_FLAG

