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

def check_access(ip, username, password):
    # Method 1: SSH via password
    argv = [
        "sshpass", "-p", password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=no",
        f"{username}@{ip}",
        "echo 1"
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        out = proc.stdout.strip()
        err = proc.stderr.strip()
        status = proc.returncode
        print(out)
    except subprocess.TimeoutExpired:
        print("[-] SSH via Password timeout after 5s")
    except Exception as e:
        print("[-] SSH via Password error:", e)


    # Method 2: Watershell
    # python3 watershell-cli.py -t 192.168.204.131 -p 53 -c id
    argv = [
        "python3", "watershell-cli.py", "-t", f"{ip}", "-p", "53", "-c", "echo 1"
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        out = proc.stdout.strip()
        err = proc.stderr.strip()
        status = proc.returncode
        print(out)
    except subprocess.TimeoutExpired:
        print("[-] SSH via Password timeout after 5s")
    except Exception as e:
        print("[-] SSH via Password error:", e)

    
    
def main():
    if len(sys.argv) != 4:
        print("Usage: python3 check_boxes_for_access.py <ip_range> <username> <password>")
        raise SystemExit(1)
    ip_range, username, password = sys.argv[1:4]
    ips = parse_ip_range(ip_range)

    for ip in ips:
        check_access(ip, username, password)

if __name__ == "__main__":
    main()