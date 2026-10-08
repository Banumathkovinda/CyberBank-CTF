"""
CyberBank: Operation BlackVault
Challenge & Three-Level Progressive Hint Seeder

Initializes the six canonical CTF challenge stages with SHA-256 flag hashes,
metadata, points, descriptions, stage dependency chain, and 3-level progressive hints.

Points:
    Stage 1 = 100
    Stage 2 = 100
    Stage 3 = 150
    Stage 4 = 150
    Stage 5 = 200
    Stage 6 = 300
    Total   = 1000

Hint Penalties:
    Hint 1 = 10%
    Hint 2 = 20%
    Hint 3 = 30%
"""

from extensions import db
from models import Challenge, Hint, User, Score
from flag_service import hash_flag


CHALLENGES_DATA = [
    {
        "stage_number": 1,
        "title": "Digital Footprint",
        "domain": "osint",
        "difficulty": "easy",
        "points": 100,
        "description": "CyberBank employees have left operational traces across public repositories and forum posts. Gather intelligence on target employees and extract the initial access credential.",
        "objective": "Analyze public employee metadata and trace leaks to retrieve the stage 1 clearance flag.",
        "flag_plaintext": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}",
        "dependency_stage": None,
        "hints": [
            {
                "hint_number": 1,
                "penalty_percentage": 10,
                "hint_text": "Start by identifying the important domain-related information.",
            },
            {
                "hint_number": 2,
                "penalty_percentage": 20,
                "hint_text": "Investigate the available DNS/public information.",
            },
            {
                "hint_number": 3,
                "penalty_percentage": 30,
                "hint_text": "Correlate the information rather than relying on a single clue.",
            },
        ],
    },
    {
        "stage_number": 2,
        "title": "Hidden in Plain Sight",
        "domain": "stego",
        "difficulty": "easy",
        "points": 100,
        "description": "A rogue insider within CyberBank has exfiltrated sensitive wire documentation concealed inside promotional multimedia files. Analyze the visual and acoustic layers to recover the hidden data.",
        "objective": "Detect steganographic anomalies and extract concealed secret data from media files.",
        "flag_plaintext": "CBANK{STEGO_h1dd3n_sp3ctrum_4491}",
        "dependency_stage": 1,
        "hints": [
            {
                "hint_number": 1,
                "penalty_percentage": 10,
                "hint_text": "Look at the metadata of the file.",
            },
            {
                "hint_number": 2,
                "penalty_percentage": 20,
                "hint_text": "Verify if the file holds any further hidden information.",
            },
            {
                "hint_number": 3,
                "penalty_percentage": 30,
                "hint_text": "Think of a classic stego/file-analysis tool.",
            },
        ],
    },
    {
        "stage_number": 3,
        "title": "Broken Banking Portal",
        "domain": "web",
        "difficulty": "medium",
        "points": 150,
        "description": "CyberBank's web portal exhibits multiple critical flaws including SQL Injection and Insecure Direct Object References. Bypass login mechanisms and elevate access to retrieve internal transaction ledgers.",
        "objective": "Exploit web application vulnerabilities to bypass authentication and dump secure ledger flags.",
        "flag_plaintext": "CBANK{WEB_sqli_byp4ss_v4ult_7721}",
        "dependency_stage": 2,
        "hints": [
            {
                "hint_number": 1,
                "penalty_percentage": 10,
                "hint_text": "Examine the HTTP requests from an application.",
            },
            {
                "hint_number": 2,
                "penalty_percentage": 20,
                "hint_text": "Use an HTTP interception proxy to inspect request parameters.",
            },
            {
                "hint_number": 3,
                "penalty_percentage": 30,
                "hint_text": "Compare the way the application accesses different resources.",
            },
        ],
    },
    {
        "stage_number": 4,
        "title": "The Banker's Secret Code",
        "domain": "crypto",
        "difficulty": "medium",
        "points": 150,
        "description": "CyberBank's incident response team recovered a suspicious encoded message from the Director-level VPN tunnel. The communication is believed to contain authorization codes associated with the attacker. Analyze the supplied data, identify the encoding or cryptographic transformations applied, and recover the original information.",
        "objective": "Decode the intercepted multi-layer encoded communication to recover the hidden authorization flag.",
        "flag_plaintext": "CBANK{CRYPTO_b4nk3r_c1ph3r_br34k_3310}",
        "dependency_stage": 3,
        "hints": [
            {
                "hint_number": 1,
                "penalty_percentage": 10,
                "hint_text": "Determine whether the data is encoding or encryption.",
            },
            {
                "hint_number": 2,
                "penalty_percentage": 20,
                "hint_text": "Consider common classical transformations.",
            },
            {
                "hint_number": 3,
                "penalty_percentage": 30,
                "hint_text": "Use an analysis tool to experiment with transformations quickly.",
            },
        ],
    },
    {
        "stage_number": 5,
        "title": "Digital Crime Scene",
        "domain": "Digital Forensics",
        "difficulty": "Moderate-Hard",
        "points": 200,
        "description": "CyberBank's security operations team isolated a suspicious workstation (WS-INVEST-SEC04) following alerts of unauthorized access and potential data exfiltration. Digital forensics investigators seized authentication logs, web access logs, application traces, network packet captures, and user scratchpad notes from the machine. Analyze and correlate these artefacts across the intrusion timeline to determine how the breach occurred and recover the authorization flag from the exfiltration stream.",
        "objective": "Analyze and correlate the seized multi-source digital artefacts (auth logs, web access logs, application events, and PCAP) to reconstruct the attack timeline and recover the forensic flag.",
        "flag_plaintext": "CBANK{FORENSICS_dchen_9f88c2_exf1l_8443}",
        "dependency_stage": 4,
        "hints": [
            {
                "hint_number": 1,
                "penalty_percentage": 10,
                "hint_text": "Begin by identifying the different evidence sources.",
            },
            {
                "hint_number": 2,
                "penalty_percentage": 20,
                "hint_text": "Look for timestamps that can connect multiple artifacts.",
            },
            {
                "hint_number": 3,
                "penalty_percentage": 30,
                "hint_text": "Compare the network evidence with the system logs.",
            },
        ],
    },
    {
        "stage_number": 6,
        "title": "BlackVault Server",
        "domain": "Linux / System Security",
        "difficulty": "Hard",
        "points": 300,
        "description": "Evidence discovered during Stage 05 identifies an internal CyberBank system known as BLACKVAULT. BlackVault is a controlled, isolated Linux server that contains the final evidence required to complete Operation BlackVault. Enumerate the target host, investigate services, files, permissions, and configuration, identify the security misconfiguration, and recover the final master flag.",
        "objective": "Perform service and Linux system enumeration on the BlackVault server, discover the privileged configuration weakness, escalate permissions, and recover the master flag.",
        "flag_plaintext": "CBANK{LINUX_r00t_bl4ckv4ult_m4st3r_5519}",
        "dependency_stage": 5,
        "hints": [
            {
                "hint_number": 1,
                "penalty_percentage": 10,
                "hint_text": "Begin by enumerating system and service information.",
            },
            {
                "hint_number": 2,
                "penalty_percentage": 20,
                "hint_text": "Check permissions and the services that are running.",
            },
            {
                "hint_number": 3,
                "penalty_percentage": 30,
                "hint_text": "Search for security weaknesses that link the discovered service with system settings.",
            },
        ],
    },
]


def seed_challenges() -> list[Challenge]:
    """
    Idempotently seeds the 6 challenge records and 18 three-level hints into MySQL.
    Establishes the dependency chain (Stage 1 -> Stage 2 -> Stage 3 -> Stage 4 -> Stage 5 -> Stage 6).
    """
    stage_to_challenge = {}

    # First pass: Create or update challenges without dependencies
    for item in CHALLENGES_DATA:
        challenge = Challenge.query.filter_by(stage_number=item["stage_number"]).first()
        flag_hash_val = hash_flag(item["flag_plaintext"])

        if challenge is None:
            challenge = Challenge(
                stage_number=item["stage_number"],
                title=item["title"],
                domain=item["domain"],
                difficulty=item["difficulty"],
                points=item["points"],
                description=item["description"],
                objective=item["objective"],
                flag_hash=flag_hash_val,
                is_active=True,
            )
            db.session.add(challenge)
        else:
            challenge.title = item["title"]
            challenge.domain = item["domain"]
            challenge.difficulty = item["difficulty"]
            challenge.points = item["points"]
            challenge.description = item["description"]
            challenge.objective = item["objective"]
            challenge.flag_hash = flag_hash_val
            challenge.is_active = True

        db.session.flush()
        stage_to_challenge[item["stage_number"]] = challenge

    # Second pass: Set dependency IDs
    for item in CHALLENGES_DATA:
        dep_stage = item["dependency_stage"]
        current_chal = stage_to_challenge[item["stage_number"]]
        if dep_stage is not None and dep_stage in stage_to_challenge:
            current_chal.dependency_id = stage_to_challenge[dep_stage].id
        else:
            current_chal.dependency_id = None

    # Third pass: Seed hints for each challenge
    for item in CHALLENGES_DATA:
        chal = stage_to_challenge[item["stage_number"]]
        for hint_item in item.get("hints", []):
            h = Hint.query.filter_by(
                challenge_id=chal.id,
                hint_number=hint_item["hint_number"],
            ).first()

            if h is None:
                h = Hint(
                    challenge_id=chal.id,
                    hint_number=hint_item["hint_number"],
                    penalty_percentage=hint_item["penalty_percentage"],
                    hint_text=hint_item["hint_text"],
                )
                db.session.add(h)
            else:
                h.penalty_percentage = hint_item["penalty_percentage"]
                h.hint_text = hint_item["hint_text"]

    db.session.commit()
    return list(stage_to_challenge.values())


def seed_default_users():
    """Ensure lecturer evaluation accounts exist idempotently."""
    admin = User.query.filter_by(username="adminctf").first()
    if not admin:
        old_admin = User.query.filter_by(username="admin").first()
        if old_admin:
            admin = old_admin
            admin.username = "adminctf"
            admin.email = "adminctf@cyberbank.local"
            admin.role = "admin"
            admin.set_password("Adminctf954#")
        else:
            admin = User(username="adminctf", email="adminctf@cyberbank.local", role="admin")
            admin.set_password("Adminctf954#")
            db.session.add(admin)
            db.session.add(Score(user=admin, total_score=0))
    else:
        admin.role = "admin"
        admin.set_password("Adminctf954#")

    demo_user = User.query.filter_by(username="operative_demo").first()
    if not demo_user:
        demo_user = User(username="operative_demo", email="demo@cyberbank.local", role="player")
        demo_user.set_password("OperativePass123!")
        db.session.add(demo_user)
        db.session.add(Score(user=demo_user, total_score=0))

    db.session.commit()


if __name__ == "__main__":
    from app import create_app
    app = create_app()
    with app.app_context():
        results = seed_challenges()
        seed_default_users()
        print(f"Seeded {len(results)} challenges, hints, and default evaluation users successfully.")
