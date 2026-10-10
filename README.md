# CyberBank: Operation BlackVault

> **An Educational Multi-Stage Cybersecurity Penetration Testing Play Box**  
> **Course / Module:** IE3132 Penetration Testing — Assignment 02  
> **Deliverable:** CTF Play Box Implementation – Working Box Demonstration  
> **Environment:** Self-Contained Docker Compose Multi-Container Architecture

---

## Academic & Submission Information

| Specification | Project Details |
| :--- | :--- |
| **Project Title** | **CyberBank: Operation BlackVault** |
| **Module Code** | **IE3132 Penetration Testing** |
| **Assessment** | **Assignment 02 — CTF Play Box Working Demonstration** |
| **Academic Context** | Implementation and verification of the Assignment 01 design into a self-contained play box |
| **Target Architecture** | Docker Compose multi-container stack (Flask, MySQL 8.0, Linux SSH, Vulnerable Web App) |
| **Supported OS** | Windows 10/11 (PowerShell), macOS (zsh), Linux (bash) |

### Group Members & Technical Responsibilities

| Group Member | Student Registration ID | Email | Technical Role | Primary Contribution Scope |
| :--- | :---: | :---: | :---: | :--- |
| **BLBK Bogahapitiya** | **IT24102626** | `banumathkovinda954@gmail.com` | **Member 1** | **CTF Platform & Architecture**: Flask core, Docker Compose stack, database modeling, authentication, live countdown timer, and health check. |
| **Arachchi B A A A B** | **IT24102592** | `alokaashen777@gmail.com` | **Member 2** | **Challenge Design A (Stages 1–3)**: OSINT developer dossier, multi-layer steganography, IDOR banking application, and automated solver. |
| **Kumarasinghe KWTP** | **IT24102485** | `pasindukumarasinghe200@gmail.com` | **Member 3** | **Challenge Design B (Stages 4–6)**: Hex/ROT13 cipher memo, DFIR log/PCAP evidence synthesis, Linux privilege escalation target, and automated solver. |
| **Ariyapperuma** | **IT24103108** | `ariyapperumadenith@gmail.com` | **Member 4** | **Integration, Testing & Quality Assurance**: Pytest test suite (116 tests), anti-cheat validation, end-to-end integration test script, and technical documentation. |

---

## Lecturer Quick-Start (3-Step Deployment)

The play box is engineered to deploy with zero manual setup. Follow these three commands from the project root:

### Step 1: Environment Configuration
```powershell
# Copy the environment template to active configuration
cp .env.example .env
```
*(On Windows PowerShell, you can also run: `Copy-Item .env.example .env`)*

### Step 2: Build & Start the Play Box
```bash
docker compose up -d --build
```

### Step 3: Access the CTF Platform
Open your browser and navigate to:
- **CTF Platform Dashboard:** [http://localhost:5000](http://localhost:5000)

### Pre-Seeded Evaluation Credentials
For immediate evaluation without manual registration, the database includes pre-seeded accounts:

| Portal / Target | Username / Callsign | Password | Role / Access Level |
| :--- | :---: | :---: | :--- |
| **CTF Web Platform** | `admin` | `AdminPass123!` | Administrator (Unrestricted View & Admin Console) |
| **CTF Web Platform** | `operative_demo` | `OperativePass123!` | Standard Operative / Player |
| **Stage 03 Banking App** | `customer_user` | `Password123!` | Auditing Customer Account (`account_id=1002`) |
| **Stage 06 Linux Server** | `analyst` | `BlackVault2026!` | Low-privilege SSH user on `localhost:2222` |

---

## 1. Setup Instructions

### 1.1 Prerequisites
Ensure the following host tools are installed:
- **Docker Desktop** (version 24.0+ recommended) or **Docker Engine with Docker Compose v2**
- **Python 3.10+** (required for local test execution and verification scripts)
- **Git** / **Terminal** (PowerShell on Windows, Bash/Zsh on Linux/macOS)
- **OpenSSH Client** (standard on Windows 10/11 and Unix systems)

### 1.2 Host Port Requirements
Ensure the following ports are available on your host machine:
- **`5000`** &mdash; Main CTF Web Platform
- **`8080`** &mdash; Stage 03 Vulnerable Banking Portal
- **`2222`** &mdash; Stage 06 BlackVault SSH Server

*(Note: MySQL internal port `3306` is restricted to the internal Docker network and is not exposed to the host.)*

### 1.3 Step-by-Step Installation
1. Extract the submitted archive or clone the repository:
   ```bash
   cd CyberBank-CTF
   ```
2. Verify or customize `.env`:
   ```bash
   # Create .env from template if not already present
   cp .env.example .env
   ```
   The default configuration is ready for instant execution without modifying credentials.

3. Build the container images:
   ```bash
   docker compose build
   ```

---

## 2. Run Instructions

### 2.1 Starting Services
Launch the complete multi-container environment in the background:
```bash
docker compose up -d
```

### 2.2 Verifying Service Health
Check that all containers are active:
```bash
docker compose ps
```
Expected running containers:
- `cyberbank-platform` &mdash; `Up` (mapped to `0.0.0.0:5000->5000`)
- `cyberbank-stage3-web` &mdash; `Up` (mapped to `0.0.0.0:8080->8080`)
- `cyberbank-blackvault` &mdash; `Up` (mapped to `0.0.0.0:2222->22`)
- `cyberbank-db` &mdash; `Up` (internal network MySQL)

### 2.3 Automated Diagnostic Verification
Execute the Member 1 diagnostic script to verify socket listeners, HTTP endpoints, container states, and database reachability:
```bash
python scripts/member1/health_check.py
```
Expected output:
```text
[1] Host Port & Socket Listening Verification:
  [PASS] Platform Web Server (Port 5000) - 127.0.0.1:5000
  [PASS] Stage 03 Banking Portal (Port 8080) - 127.0.0.1:8080
  [PASS] Stage 06 BlackVault SSH (Port 2222) - 127.0.0.1:2222
[2] Application Service & Health Endpoint Verification:
  [PASS] Platform Telemetry (/health) - HTTP 200 - DB: connected | Status: healthy
  [PASS] Stage 03 Portal (/login) - HTTP 200
[3] Docker Container & Network Orchestration:
  [PASS] Container 'cyberbank-platform' - Running
  [PASS] Container 'cyberbank-stage3-web' - Running
  [PASS] Container 'cyberbank-blackvault' - Running
  [PASS] Docker Network 'cyberbank-network' - Created & Active
-----------------------------------------------------------------
 Overall Infrastructure Status: HEALTHY (100% OPERATIONAL)
```

### 2.4 Running the Automated Test Suite
To execute all 116 automated unit, integration, and security tests across the platform:
```bash
python -m pytest tests
```
*Result: 116 passed across all 11 test modules.*

### 2.5 Stopping the Play Box
To gracefully stop the running containers:
```bash
docker compose down
```

---

## 3. Reset Instructions

The play box provides three distinct reset tiers to suit different evaluation scenarios:

### Tier 1: Challenge-Only Reset (Recommended for Continuous Testing)
Restores evidence artifacts, resets vulnerable challenge databases, and restarts challenge containers **while preserving registered student accounts, leaderboards, and scores**:
```bash
python scripts/reset_challenges.py --challenges-only
```
*(Or simply: `python scripts/reset_challenges.py`)*

### Tier 2: Full Development Reset (Complete Clean Slate)
Rebuilds challenge evidence, wipes challenge database records, and reseeds the 6 stages, 18 hints, and default evaluation users from scratch:
```bash
python scripts/reset_challenges.py --full-reset --confirm
```

### Tier 3: Docker-Level Clean Purge
To completely purge Docker volumes and recreate the entire stack:
```bash
# 1. Stop containers and remove named volumes
docker compose down -v

# 2. Re-launch and re-seed automatically
docker compose up -d --build
```

---

## 4. Architecture & Container Orchestration

```
[ Operative / Evaluator Browser ]
               |
               | HTTP (Port 5000)  - CyberBank CTF Web Platform
               | HTTP (Port 8080)  - Stage 03 Vulnerable Banking Portal
               | SSH  (Port 2222)  - Stage 06 Linux Target
               v
+-----------------------------------------------------------------------------------+
| Host Port Binding                                                                 |
+-----------------------------------------------------------------------------------+
       |                       |                               |
       | Port 5000             | Port 8080                     | Port 2222
       v                       v                               v
+-----------------------+ +-----------------------+ +--------------------------------+
| cyberbank-platform    | | cyberbank-stage3-web  | | cyberbank-blackvault           |
| (Flask Core Web App)  | | (Stage 03 IDOR App)   | | (Stage 06 Debian Target)       |
| Python 3.12 / Gunicorn| | Python 3.12 / Flask   | | OpenSSH (SSH Port 2222)        |
| Non-root: appuser     | | Isolated SQLite       | | Low-priv: analyst              |
+-----------------------+ +-----------------------+ +--------------------------------+
       |                                                           |
       | Internal Port 3306                                        |
       v                                                           |
+------------------------------------+                             |
| cyberbank-db                       |                             |
| (MySQL 8.0 Server)                 |                             |
| Volume: mysql-data                 |                             |
| Host: Not exposed (Internal Only)  |                             |
+------------------------------------+                             |
       ^                                                           |
       +===========================================================+
                 Isolated Bridge Network: cyberbank-network
```

---

## 5. Challenge Stages & Progression Matrix

The play box implements a strict sequential progression. An operative cannot view, download, or submit flags for Stage $N+1$ until Stage $N$ is validated and scored.

| Stage | Code | Title | Domain | Difficulty | Points | Objective & Flaw Overview |
| :---: | :---: | :--- | :--- | :---: | :---: | :--- |
| **01** | `CB-01` | **Digital Footprint** | OSINT / Recon | Easy | 100 | Inspect public git commit logs and developer chat leaks to recover staging credentials. |
| **02** | `CB-02` | **Hidden in Plain Sight** | Steganography | Easy | 100 | Extract password-protected ZIP archive embedded in promotional PNG asset via metadata & binwalk. |
| **03** | `CB-03` | **Broken Banking Portal** | Web Security | Moderate | 150 | Exploit IDOR / BOLA on customer banking portal to access Master Reserve account ledger. |
| **04** | `CB-04` | **The Banker's Secret Code** | Cryptography | Moderate | 150 | Decode intercepted hex stream and reverse classical ROT13 substitution to recover director code. |
| **05** | `CB-05` | **Digital Crime Scene** | Digital Forensics | Moderate-Hard | 200 | Cross-reference authentication logs, web access logs, and Wireshark PCAP to trace TLS exfiltration. |
| **06** | `CB-06` | **BlackVault Server** | Linux / Privesc | Hard | 300 | SSH into Debian server, discover automated root cron job, exploit misconfigured permissions for root flag. |

### Flag Format & Validation
- **Standard Format:** `CBANK{unique_flag_identifier}`
- **Verification:** Flags are validated server-side using constant-time cryptographic **SHA-256** matching. Flag plaintext is never transmitted to the client.
- **Anti-Cheat:** Honeypot flags and anti-AI canary tokens trigger audit logging and immediate submission rejection.

### Progressive Hints System
Each stage includes three progressive hints with tiered score deductions:
- **Hint 1:** -10% point penalty
- **Hint 2:** -20% point penalty
- **Hint 3:** -30% point penalty
*(Maximum cumulative penalty: 60%. Minimum achievable score per stage: 40% of base points.)*

---

## 6. Individual Member Automation & Verification Scripts

In accordance with Assignment 02 specifications, each group member maintains a dedicated Python automation or verification script:

### Member 1: [scripts/member1/health_check.py](file:///c:/Users/ASUS/Desktop/bank%20CTF/CyberBank-CTF/scripts/member1/health_check.py)
- **Role:** Platform Architecture & Infrastructure Verification
- **Function:** Automated health probe testing TCP socket listeners (5000, 8080, 2222), HTTP `/health` telemetry, database connectivity, and Docker container lifecycles.
- **Run:** `python scripts/member1/health_check.py`

### Member 2: [scripts/member2/stage3_solver.py](file:///c:/Users/ASUS/Desktop/bank%20CTF/CyberBank-CTF/scripts/member2/stage3_solver.py)
- **Role:** Web Security & Challenge Design A
- **Function:** Automated programmatic verification script that logs into the vulnerable banking portal, iterates through account parameters, and demonstrates BOLA/IDOR exploitation.
- **Run:** `python scripts/member2/stage3_solver.py`

### Member 3: [scripts/member3/stage6_solver.py](file:///c:/Users/ASUS/Desktop/bank%20CTF/CyberBank-CTF/scripts/member3/stage6_solver.py)
- **Role:** Linux Privilege Escalation & Challenge Design B
- **Function:** Automated privilege escalation exploit script for the BlackVault Debian target, demonstrating configuration tampering via group-writable `/etc/blackvault/backup.conf` and privileged execution via `sudo /opt/blackvault/bin/vault_backup.sh` to extract the master root flag.
- **Run:** `python scripts/member3/stage6_solver.py`

### Member 4: [scripts/member4/integration_test.py](file:///c:/Users/ASUS/Desktop/bank%20CTF/CyberBank-CTF/scripts/member4/integration_test.py)
- **Role:** Integration, Testing & Quality Assurance
- **Function:** Comprehensive end-to-end integration test automating user registration, sequential flag submissions, locked stage boundary enforcement, and scoreboard updates.
- **Run:** `python scripts/member4/integration_test.py`

---

## 7. Troubleshooting & Diagnostics

| Symptom | Probable Cause | Corrective Action |
| :--- | :--- | :--- |
| **Port 5000 already in use** | Another local service (e.g. AirPlay, local Flask) | Stop the conflicting process or change host port in [docker-compose.yml](file:///c:/Users/ASUS/Desktop/bank%20CTF/CyberBank-CTF/docker-compose.yml) (`"5050:5000"`). |
| **Cannot connect to Docker daemon** | Docker Desktop is stopped | Start Docker Desktop and wait until the engine status shows "Engine running". |
| **Database connection error** | MySQL container initializing on first boot | Allow 10–15 seconds for MySQL initialization. Verify with `python scripts/test_db_connection.py`. |
| **Stage 3 portal login fails** | SQLite database altered during manual test | Run `python scripts/reset_challenges.py --challenges-only` to restore default database state. |
| **SSH Host Key Warning on Port 2222** | Rebuilt container with fresh host keys | Remove old key from known hosts: `ssh-keygen -R [localhost]:2222`. |
| **2-Hour Mission Window Expired** | Countdown timer reached 00:00:00 | Click the **"Restart Mission Timer"** button on the Mission Matrix HUD or navigate to `/mission/reset-timer`. |

---

## 8. Security & Ethical Boundaries
- **Educational Sandbox:** All challenges, employee records, domain names (`cyberbank.local`), IP addresses (`198.51.100.0/24`), and credentials are entirely fictitious and engineered solely for educational cybersecurity training.
- **Isolation:** Network boundaries prevent challenge containers from initiating arbitrary outbound connections to external public infrastructure.
- **Resource Limits:** Docker containers enforce memory, CPU, and PID limits to protect host resources during penetration testing demonstrations.

---
*CyberBank: Operation BlackVault &copy; 2024–2026. Prepared for IE3132 Penetration Testing Assignment 02.*
