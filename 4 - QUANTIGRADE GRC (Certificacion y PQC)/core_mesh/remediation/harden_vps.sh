#!/bin/bash
# ==============================================================================
# QUANTIGRADE GCR - ADVANCED LINUX HOST/VPS HARDENING SCRIPT
# Aligns with ENS Categoría Alta, NIS2 Art. 21, and CIS Benchmark
# Zero-Docker by default (Native Linux Service Optimization)
# ==============================================================================

set -e

echo "🚀 Iniciando Protocolo de Hardening Linux Host..."

# 1. Update Core System
echo "📦 Actualizando sistema base y paquetes de seguridad..."
if command -v apt-get &> /dev/null; then
    apt-get update && apt-get upgrade -y
    apt-get install -y curl wget git htop ufw fail2ban unattended-upgrades apt-transport-https ca-certificates gnupg lsb-release
elif command -v dnf &> /dev/null; then
    dnf upgrade -y
    dnf install -y curl wget git htop firewalld fail2ban
fi

# 2. Advanced Firewall (UFW)
if command -v ufw &> /dev/null; then
    echo "🧱 Configurando Firewall Avanzado (UFW)..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw limit ssh
    echo "y" | ufw enable || true
fi

# 3. SSH Hardening
if [ -f /etc/ssh/sshd_config ]; then
    echo "🛡️ Blindando configuracion SSH..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    systemctl restart sshd || systemctl restart ssh || true
fi

# 4. Fail2Ban Configuration
if command -v fail2ban-client &> /dev/null; then
    echo "🚫 Configurando Fail2Ban..."
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
EOF
    systemctl enable fail2ban || true
    systemctl restart fail2ban || true
fi

# 5. Sysctl Network & Kernel Hardening (RFC 800-53 / CIS Level 2)
echo "🧠 Ajustando parametros defensivos de Kernel (sysctl)..."
cat > /etc/sysctl.d/99-quantigrade-security.conf <<EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
# Send redirects disabled
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Block SYN flood attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
# ASLR enforcement
kernel.randomize_va_space = 2
EOF
sysctl -p /etc/sysctl.d/99-quantigrade-security.conf || true

echo "✅ HARDENING LINUX COMPLETADO EXITOSAMENTE."

