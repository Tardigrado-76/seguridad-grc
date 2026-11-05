#!/bin/bash
# ==============================================================================
# TAVILGA - ADVANCED VPS HARDENING SCRIPT (2026 EDITION)
# Optimized for: Hostinger KVM2 (Ubuntu 24.04 LTS)
# ==============================================================================

set -e

echo "🚀 Iniciando Protocolo de Hardening TAVILGA..."

# 1. Update Core System
echo "📦 Actualizando sistema base..."
apt update && apt upgrade -y
apt install -y curl wget git htop ufw fail2ban unattended-upgrades apt-transport-https ca-certificates gnupg lsb-release

# 2. Configure Automatic Security Updates
echo "🔄 Configurando actualizaciones automáticas..."
echo 'Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};' > /etc/apt/apt.conf.d/50unattended-upgrades

# 3. Advanced Firewall (UFW)
echo "🧱 Configurando Firewall Avanzado..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh         # SSH (Consider changing port later)
ufw allow 80/tcp      # HTTP
ufw allow 443/tcp     # HTTPS
ufw allow 3000/tcp    # Cronos Frontend
ufw allow 3001/tcp    # Cronos Backend
ufw allow 5173/tcp    # 3D Configurator
# Rate limiting for SSH
ufw limit ssh
echo "y" | ufw enable

# 4. SSH Hardening
echo "🛡️ Blindando SSH..."
# Backup config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
# Disable Root Login & Password Auth
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
# Restart SSH
systemctl restart sshd

# 5. Fail2Ban Configuration
echo "🚫 Configurando Fail2Ban..."
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime  = 10m
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
EOF
systemctl enable fail2ban
systemctl restart fail2ban

# 6. Docker Hardening & Optimization for KVM2
echo "🐳 Optimizando Docker..."
# Install latest Docker if not present
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
fi

# Daemon Config for Security & Logs
cat > /etc/docker/daemon.json <<EOF
{
  "icc": false,
  "no-new-privileges": true,
  "live-restore": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
systemctl restart docker

# 7. Sysctl Network Hardening
echo "🧠 Ajustando Kernel (sysctl)..."
cat > /etc/sysctl.d/99-tavilga-security.conf <<EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
# Send redirects, if router, but this is host
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
EOF
sysctl -p /etc/sysctl.d/99-tavilga-security.conf

echo "✅ HARDENING COMPLETADO EXITOSAMENTE."
echo "⚠️  IMPORTANTE: Asegúrese de tener una clave SSH configurada para su usuario antes de cerrar la sesión actual."
