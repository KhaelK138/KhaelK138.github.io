#!/usr/bin/env python3
import re
import sys
import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# adjust these
MAX_WORKERS = 20
SSH_TIMEOUT = 120  # seconds per host

def parse_ip_range(ip_range):
    pattern = r'^(\d+)\.(\d+)\.(\d+(?:-\d+)?)\.(\d+(?:-\d+)?)$'
    m = re.match(pattern, ip_range)
    if not m:
        raise SystemExit("Invalid IP range format")
    a, b, c_part, d_part = m.groups()
    def expand(part):
        if '-' in part:
            s,e = map(int, part.split('-'))
            return range(s, e+1)
        v = int(part); return range(v, v+1)
    return [f"{a}.{b}.{c}.{d}" for c in expand(c_part) for d in expand(d_part)]

def run_command(ip, username, password, command, timeout=SSH_TIMEOUT):
    # build remote command: echo 'pass' | sudo -S bash -c 'command'
    remote_cmd = "echo {} | sudo -S bash -c {}".format(
        shlex.quote(password),
        shlex.quote(command)
    )
    argv = [
        "sshpass", "-p", password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=no",
        f"{username}@{ip}",
        remote_cmd
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout.strip()
        err = proc.stderr.strip()
        status = proc.returncode
        return ip, status, out, err
    except subprocess.TimeoutExpired:
        return ip, -1, "", f"timeout after {timeout}s"
    except Exception as e:
        return ip, -2, "", str(e)

def main():
    if len(sys.argv) != 5:
        print("Usage: ssh_across_ips.py <ip_range> <username> <password> <command>")
        raise SystemExit(1)
    ip_range, username, password, command = sys.argv[1:5]
    ips = parse_ip_range(ip_range)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(run_command, ip, username, password, command): ip for ip in ips}
        for fut in as_completed(futures):
            ip, rc, out, err = fut.result()
            tag = "[OK]" if rc == 0 else ("[TIMEOUT]" if rc == -1 else "[ERR]")
            print(f"{tag} {ip} (rc={rc})")
            if out:
                print(f"--- stdout ---\n{out}")
            if err:
                print(f"--- stderr ---\n{err}")

if __name__ == "__main__":
    main()