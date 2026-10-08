#!/bin/bash
# ================================================================
# CyberBank BlackVault System Snapshot Utility
# Asset: BV-SEC-CORE-01
# WARNING: This script performs privileged vault data backups.
# ================================================================

echo "[*] Initializing BlackVault System Snapshot..."

# Load local administrator configuration if present
if [ -f /etc/blackvault/backup.conf ]; then
    echo "[*] Sourcing configuration from /etc/blackvault/backup.conf..."
    # shellcheck source=/dev/null
    source /etc/blackvault/backup.conf
fi

mkdir -p /var/backups/blackvault
cd /opt/blackvault/data 2>/dev/null || cd /tmp
tar -czf "/var/backups/blackvault/vault_backup_$(date +%s).tar.gz" . 2>/dev/null

echo "[+] BlackVault snapshot archive created in /var/backups/blackvault."
echo "[+] Snapshot routine completed."
