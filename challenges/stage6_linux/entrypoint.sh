#!/bin/bash
set -e

# Generate SSH host keys if not present
ssh-keygen -A 2>/dev/null

# Ensure permissions on sensitive files on every start (reproducible reset!)
chmod 755 /opt/blackvault/bin/vault_backup.sh
chown root:root /opt/blackvault/bin/vault_backup.sh

chown root:analyst /etc/blackvault/backup.conf
chmod 664 /etc/blackvault/backup.conf

chmod 0400 /root/blackvault_flag.txt
chown root:root /root/blackvault_flag.txt

chmod 0440 /etc/sudoers.d/analyst
chown root:root /etc/sudoers.d/analyst

# Start OpenSSH daemon
/usr/sbin/sshd

echo "[*] BlackVault Server initialized. Listening on SSH (22)."

# Keep container alive
exec tail -f /dev/null
