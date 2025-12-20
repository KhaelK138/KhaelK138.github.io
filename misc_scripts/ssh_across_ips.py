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


def run_command(ip, username, password, command, timeout=SSH_TIMEOUT):

    # build remote command: echo 'pass' | sudo -S bash -c 'command'
    if username == "root":
        remote_cmd = "bash -c {}".format(
            shlex.quote(command)
        )
    else:
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
        print("Usage: python3 ssh_across_ips.py <ip_range> <username> <password> <command>")
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
                print(f"\033[32m[+]\033[0m Output for {ip}: {out}")

if __name__ == "__main__":
    main()