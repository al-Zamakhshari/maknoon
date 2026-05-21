#!/bin/sh
set -e

# Create dedicated system user if it does not already exist.
if ! id -u maknoon >/dev/null 2>&1; then
    useradd --system \
            --no-create-home \
            --shell /usr/sbin/nologin \
            --comment "Maknoon MCP server" \
            maknoon
fi

# Create data directory with tight permissions.
mkdir -p /var/lib/maknoon
chown maknoon:maknoon /var/lib/maknoon
chmod 700 /var/lib/maknoon

# Create config directory for TLS certs and config.json.
mkdir -p /etc/maknoon
chmod 750 /etc/maknoon

# Reload systemd so the new unit is visible.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
