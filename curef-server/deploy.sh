#!/usr/bin/env bash
# Deploy the tcl-curef server as a hardened systemd service.
# Usage:  scp server.js -> /tmp/tcl-curef-server.js first, then:
#           TCL_CUREF_KEY=<key> bash deploy.sh
# The key ships in the open-source client (anti-spam only), so it isn't secret.
set -euo pipefail

APP_DIR=/opt/tcl-curef-server
DATA_DIR=/var/lib/tcl-curef
ENV_FILE=/etc/tcl-curef.env
UNIT=/etc/systemd/system/tcl-curef.service
PORT="${PORT:-8788}"
API_KEY="${TCL_CUREF_KEY:-us4zI1xHemiIo499wgrfX_6q_7Okky5o}"

id tclcuref >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin tclcuref

mkdir -p "$APP_DIR" "$DATA_DIR"
install -o tclcuref -g tclcuref -m 644 /tmp/tcl-curef-server.js "$APP_DIR/server.js"
chown -R tclcuref:tclcuref "$DATA_DIR"; chmod 750 "$DATA_DIR"

cat > "$ENV_FILE" <<EOF
PORT=$PORT
HOST=127.0.0.1
DATA_DIR=$DATA_DIR
TCL_CUREF_KEY=$API_KEY
EOF
chmod 640 "$ENV_FILE"; chown root:tclcuref "$ENV_FILE"

NODE_BIN="$(command -v node)"
cat > "$UNIT" <<EOF
[Unit]
Description=tcl-curef community device registry
After=network.target

[Service]
Type=simple
User=tclcuref
Group=tclcuref
EnvironmentFile=$ENV_FILE
ExecStart=$NODE_BIN $APP_DIR/server.js
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable tcl-curef >/dev/null 2>&1
systemctl restart tcl-curef
sleep 1
systemctl --no-pager --full status tcl-curef | head -8
