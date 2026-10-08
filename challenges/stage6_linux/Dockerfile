# ============================================
# CyberBank: Operation BlackVault
# Stage 06: BlackVault Server Dockerfile
# ============================================

FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install core packages needed for realistic Linux system enumeration
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    sudo \
    procps \
    net-tools \
    iproute2 \
    curl \
    python3 \
    nano \
    vim-tiny \
    tar \
    gzip \
    findutils \
    && rm -rf /var/lib/apt/lists/*

# Configure OpenSSH daemon
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create low-privileged challenge account 'analyst'
RUN useradd -m -s /bin/bash -u 1001 analyst && \
    echo "analyst:BlackVault2026!" | chpasswd

# Setup BlackVault directory hierarchy
RUN mkdir -p /opt/blackvault/bin /opt/blackvault/data /etc/blackvault /var/backups/blackvault

# Copy challenge assets
COPY vault_backup.sh /opt/blackvault/bin/vault_backup.sh
COPY backup.conf /etc/blackvault/backup.conf
COPY entrypoint.sh /entrypoint.sh

# Normalize line endings (CRLF -> LF)
RUN sed -i 's/\r$//' /entrypoint.sh /opt/blackvault/bin/vault_backup.sh /etc/blackvault/backup.conf

# Configure file ownership and permissions:
# 1. vault_backup.sh is executable by all, owned by root:root
RUN chmod 755 /opt/blackvault/bin/vault_backup.sh && chown root:root /opt/blackvault/bin/vault_backup.sh

# 2. backup.conf is owned by root:analyst and group-writable (intentional misconfiguration)
RUN chown root:analyst /etc/blackvault/backup.conf && chmod 664 /etc/blackvault/backup.conf

# 3. Entrypoint executable
RUN chmod 755 /entrypoint.sh

# 4. Sudoers rule: analyst can run vault_backup.sh as root without password
RUN echo "analyst ALL=(root) NOPASSWD: /opt/blackvault/bin/vault_backup.sh" > /etc/sudoers.d/analyst && \
    chmod 0440 /etc/sudoers.d/analyst

# 5. Protected final flag in /root/blackvault_flag.txt (only root can read)
RUN echo "CBANK{LINUX_r00t_bl4ckv4ult_m4st3r_5519}" > /root/blackvault_flag.txt && \
    chmod 0400 /root/blackvault_flag.txt && \
    chown root:root /root/blackvault_flag.txt

# 6. Simulated internal data files for realistic enumeration
RUN echo "TRANSACTION_LEDGER_2026_MASTER_RESERVE" > /opt/blackvault/data/ledger_reserve.dat && \
    echo "STATUS: SYNCHRONIZED" > /opt/blackvault/data/node_telemetry.log

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
