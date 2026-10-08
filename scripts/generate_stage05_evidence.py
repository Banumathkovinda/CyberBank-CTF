"""
CyberBank: Operation BlackVault
Stage 05 — Evidence Package Generator Script

Generates the complete digital forensics evidence package:
    - evidence/auth.log
    - evidence/web_access.log
    - evidence/application.log
    - evidence/network_capture.pcap
    - evidence/suspicious_note.txt
    - evidence/metadata.txt

Packages all artefacts into:
    platform/static/downloads/stage05_evidence.zip

All data is fictional and educational, adhering to RFC 5737 IP ranges.
"""

import hashlib
import os
import shutil
import zipfile
import sys

# Ensure scripts dir can import generate_stage05_pcap
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_stage05_pcap import create_pcap


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STAGE5_DIR = os.path.join(BASE_DIR, "challenges", "stage5_forensics")
EVIDENCE_DIR = os.path.join(STAGE5_DIR, "evidence")
DOWNLOADS_DIR = os.path.join(BASE_DIR, "platform", "static", "downloads")
ZIP_OUTPUT_PATH = os.path.join(DOWNLOADS_DIR, "stage05_evidence.zip")


AUTH_LOG_CONTENT = """Aug 16 02:14:02 WS-INVEST-SEC04 systemd[1]: Starting Daily apt download activities...
Aug 16 02:14:05 WS-INVEST-SEC04 systemd[1]: apt-daily.service: Deactivated successfully.
Aug 16 02:15:10 WS-INVEST-SEC04 sshd[14201]: Failed password for invalid user admin from 198.51.100.47 port 48110 ssh2
Aug 16 02:15:12 WS-INVEST-SEC04 sshd[14201]: Received disconnect from 198.51.100.47 port 48110:11: Bye Bye [preauth]
Aug 16 02:16:33 WS-INVEST-SEC04 sshd[14205]: Failed password for invalid user backup_svc from 198.51.100.47 port 48152 ssh2
Aug 16 02:16:34 WS-INVEST-SEC04 sshd[14205]: Received disconnect from 198.51.100.47 port 48152:11: Bye Bye [preauth]
Aug 16 02:18:02 WS-INVEST-SEC04 sshd[14212]: Failed password for operator from 198.51.100.47 port 48201 ssh2
Aug 16 02:18:04 WS-INVEST-SEC04 sshd[14212]: Received disconnect from 198.51.100.47 port 48201:11: Bye Bye [preauth]
Aug 16 02:20:19 WS-INVEST-SEC04 sshd[14220]: Failed password for j.miller from 198.51.100.47 port 48255 ssh2
Aug 16 02:20:20 WS-INVEST-SEC04 sshd[14220]: Received disconnect from 198.51.100.47 port 48255:11: Bye Bye [preauth]
Aug 16 02:22:45 WS-INVEST-SEC04 sshd[14234]: Failed password for d.chen from 198.51.100.47 port 48312 ssh2
Aug 16 02:22:46 WS-INVEST-SEC04 sshd[14234]: Received disconnect from 198.51.100.47 port 48312:11: Bye Bye [preauth]
Aug 16 02:24:18 WS-INVEST-SEC04 sshd[14250]: Accepted publickey for d.chen from 198.51.100.47 port 49822 ssh2: RSA SHA256:4tM0V7yKZP6WqE0gJ9xLv1r8bNp2sK4wX7zY3mQ6tA
Aug 16 02:24:18 WS-INVEST-SEC04 sshd[14250]: pam_unix(sshd:session): session opened for user d.chen(uid=1004) by (uid=0)
Aug 16 02:24:19 WS-INVEST-SEC04 systemd-logind[782]: New session 42 of user d.chen.
Aug 16 02:25:02 WS-INVEST-SEC04 sudo:   d.chen : TTY=pts/2 ; PWD=/home/d.chen ; USER=root ; COMMAND=/bin/cat /etc/shadow
Aug 16 02:25:02 WS-INVEST-SEC04 sudo: pam_unix(sudo:auth): authentication failure; logname=d.chen uid=1004 euid=0 tty=/dev/pts/2 ruser=d.chen rhost= user=d.chen
Aug 16 02:26:01 WS-INVEST-SEC04 CRON[14300]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Aug 16 02:26:01 WS-INVEST-SEC04 CRON[14300]: pam_unix(cron:session): session closed for user root
Aug 16 02:40:55 WS-INVEST-SEC04 sshd[14250]: pam_unix(sshd:session): session closed for user d.chen
Aug 16 02:40:56 WS-INVEST-SEC04 systemd-logind[782]: Session 42 of user d.chen logged out.
"""

WEB_ACCESS_LOG_CONTENT = """198.51.100.47 - - [16/Aug/2026:02:26:05 +0000] "GET /api/v1/health HTTP/1.1" 200 68 "-" "Mozilla/5.0 (X11; Linux x86_64) CyberSec-Audit/2.0"
198.51.100.47 - - [16/Aug/2026:02:26:12 +0000] "POST /api/v1/auth/session HTTP/1.1" 200 142 "-" "Mozilla/5.0 (X11; Linux x86_64) CyberSec-Audit/2.0"
198.51.100.47 - - [16/Aug/2026:02:27:30 +0000] "GET /api/v1/user/profile?user=d.chen&token=sess_9f88c21a44e7 HTTP/1.1" 200 512 "-" "Mozilla/5.0 (X11; Linux x86_64) CyberSec-Audit/2.0"
198.51.100.47 - - [16/Aug/2026:02:29:15 +0000] "GET /api/v1/audit/logs?session=sess_9f88c21a44e7 HTTP/1.1" 200 4096 "-" "Mozilla/5.0 (X11; Linux x86_64) CyberSec-Audit/2.0"
198.51.100.47 - - [16/Aug/2026:02:31:04 +0000] "GET /api/v1/vault/export?filter=director_tier&session=sess_9f88c21a44e7 HTTP/1.1" 403 189 "-" "Mozilla/5.0 (X11; Linux x86_64) CyberSec-Audit/2.0"
198.51.100.47 - - [16/Aug/2026:02:33:41 +0000] "POST /api/v1/admin/privilege_override?session=sess_9f88c21a44e7 HTTP/1.1" 200 230 "-" "Mozilla/5.0 (X11; Linux x86_64) CyberSec-Audit/2.0"
198.51.100.47 - - [16/Aug/2026:02:35:50 +0000] "GET /api/v1/vault/ledger_export?archive=blackvault_stage05_custody.tar.gz&session=sess_9f88c21a44e7 HTTP/1.1" 200 48291 "-" "Mozilla/5.0 (X11; Linux x86_64) CyberSec-Audit/2.0"
10.10.20.1 - - [16/Aug/2026:02:37:00 +0000] "GET /health HTTP/1.1" 200 45 "-" "Internal-Monitor/1.0"
"""

APPLICATION_LOG_CONTENT = """[2026-08-16 02:24:19.102 UTC] [INFO] [CoreAuth] New administrative SSH session established for operative 'd.chen' from origin 198.51.100.47:49822
[2026-08-16 02:26:12.441 UTC] [INFO] [SessionMgr] Session token generated: sess_9f88c21a44e7 for user 'd.chen' [Scope: AUDITOR_RO]
[2026-08-16 02:27:30.819 UTC] [INFO] [AuditTracker] Profile query executed for user d.chen
[2026-08-16 02:29:15.302 UTC] [INFO] [AuditTracker] Audit log stream accessed by session sess_9f88c21a44e7
[2026-08-16 02:31:04.112 UTC] [WARN] [VaultService] Unauthorized access attempt to /api/v1/vault/export by session sess_9f88c21a44e7. Required scope: VAULT_ADMIN
[2026-08-16 02:33:41.520 UTC] [CRIT] [SecurityFilter] Privilege bypass detected in AuthProvider module! Session sess_9f88c21a44e7 escalated: AUDITOR_RO -> VAULT_ADMIN
[2026-08-16 02:35:50.005 UTC] [INFO] [DataExporter] Archive 'blackvault_stage05_custody.tar.gz' generated for session sess_9f88c21a44e7. Payload size: 48,291 bytes
[2026-08-16 02:38:12.784 UTC] [ALERT] [NetMonitor] Outbound direct data channel initiated to external drop 203.0.113.88:8443 by session sess_9f88c21a44e7
[2026-08-16 02:38:15.932 UTC] [INFO] [NetMonitor] Outbound exfiltration transmission acknowledged by drop server 203.0.113.88:8443
[2026-08-16 02:40:55.228 UTC] [INFO] [CoreAuth] Administrative session terminated for user 'd.chen' (origin: 198.51.100.47:49822)
"""

SUSPICIOUS_NOTE_CONTENT = """================================================================
CYBERBANK DFIR CASE: CB-IR-2026-0882
WORKSTATION SEIZURE ARTIFACT — SCRATCHPAD MEMO
RECOVERED PATH: /home/d.chen/.local/share/notes_archive.txt
================================================================

[OPERATOR SCRATCHPAD]
- System Workstation: WS-INVEST-SEC04 (10.10.20.155)
- Compromised Operator Account: d.chen
- Staging External Relay: 203.0.113.88:8443
- Target Vault Archive: blackvault_stage05_custody.tar.gz

[INCIDENT RESPONSE RECONSTRUCTION INSTRUCTIONS]
An unauthorized session exfiltrated the BlackVault custody ledger.
To confirm the complete attack chain for the triage report:
1. Identify the compromised account and source IP in auth.log.
2. Note the hijacked session token generated in application.log / web_access.log.
3. Open network_capture.pcap in Wireshark and filter for HTTP traffic on TCP port 8443.
4. Follow the TCP stream to inspect the server's exfiltration response receipt.
5. Recover the forensic authorization flag to validate full incident reconstruction.
================================================================
"""

METADATA_CONTENT = """================================================================
CYBERBANK INCIDENT RESPONSE UNIT (DFIR ALPHA)
EVIDENCE CUSTODY LOG & FORENSIC METADATA
================================================================
Case ID: CB-IR-2026-0882
Incident Type: Workstation Intrusion & Unauthorized Data Exfiltration
Seized Machine: WS-INVEST-SEC04 (Asset Tag: CB-WS-09412)
IP Address: 10.10.20.155
Seizure Timestamp: 2026-08-16 04:00:00 UTC
Lead Investigator: Inspector Sarah Vance, Lead DFIR Specialist

ARTIFACT ROSTER:
1. auth.log                - System authentication and PAM session logs
2. web_access.log          - Workstation web portal proxy and API access logs
3. application.log         - CyberBank Core Vault application event traces
4. network_capture.pcap    - Perimeter packet capture covering incident window
5. suspicious_note.txt     - Scrap memorandum recovered from user profile
6. metadata.txt            - Chain of custody and forensic briefing (this document)

INVESTIGATION GUIDELINES:
- Establish a chronological attack timeline from reconnaissance to exfiltration.
- Correlate external attacker source IP (RFC 5737 TEST-NET range).
- Trace the specific user credentials hijacked and the session identifier issued.
- Analyze the packet capture stream in Wireshark to locate the unencrypted exfiltration receipt.
================================================================
"""


def generate_evidence_package():
    """Build all forensic evidence files and compile the final ZIP package."""
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)

    # 1. Write text logs
    files_to_write = {
        "auth.log": AUTH_LOG_CONTENT.strip() + "\n",
        "web_access.log": WEB_ACCESS_LOG_CONTENT.strip() + "\n",
        "application.log": APPLICATION_LOG_CONTENT.strip() + "\n",
        "suspicious_note.txt": SUSPICIOUS_NOTE_CONTENT.strip() + "\n",
        "metadata.txt": METADATA_CONTENT.strip() + "\n",
    }

    for fname, content in files_to_write.items():
        fpath = os.path.join(EVIDENCE_DIR, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Written: {fpath}")

    # 2. Generate PCAP
    pcap_path = os.path.join(EVIDENCE_DIR, "network_capture.pcap")
    create_pcap(pcap_path)

    # 3. Create ZIP archive
    print(f"[*] Packaging evidence into {ZIP_OUTPUT_PATH}...")
    with zipfile.ZipFile(ZIP_OUTPUT_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname in sorted(os.listdir(EVIDENCE_DIR)):
            fpath = os.path.join(EVIDENCE_DIR, fname)
            if os.path.isfile(fpath):
                # Archive name inside ZIP: evidence/<filename>
                arcname = os.path.join("evidence", fname).replace("\\", "/")
                zf.write(fpath, arcname)
                print(f"    -> Added {arcname} ({os.path.getsize(fpath)} bytes)")

    print(f"[+] Stage 05 Evidence Package ready at: {ZIP_OUTPUT_PATH}")
    print(f"[+] Package size: {os.path.getsize(ZIP_OUTPUT_PATH)} bytes")


if __name__ == "__main__":
    generate_evidence_package()
