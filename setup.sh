#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

info "Installing python3-aiohttp..."
apt-get install -y -q python3-aiohttp
ok "aiohttp installed"

info "Creating systemd service..."
cat > /etc/systemd/system/rust-rcon-panel.service << 'EOF'
[Unit]
Description=Rust Game Server RCON Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/steam/rcon-panel
ExecStart=/usr/bin/python3 /home/steam/rcon-panel/app.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable rust-rcon-panel
systemctl restart rust-rcon-panel
ok "Service enabled and started"

sleep 1
systemctl is-active rust-rcon-panel && echo -e "\n${GREEN}Panel is running on port 80${NC}" || echo "Check: journalctl -u rust-rcon-panel -n 20"
