# Script to add users from a text file as local and domain admins

param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("Local", "Domain")]
    [string]$Mode,

    [Parameter(Mandatory=$false)]
    [string]$UserListPath = ".\users_to_add.txt",

    [Parameter(Mandatory=$false)]
    [string]$Password = "Password1!",

    [Parameter(Mandatory=$false)]
    [string]$DomainName = $env:USERDOMAIN
)

# Define privileged groups for domain users
$PrivilegedGroups = @(
    "Domain Admins",
    "Server Operators", 
    "Backup Operators", 
    "Account Operators", 
    "DnsAdmins"
)

# Create a secure string for the password
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force

# Function to add local admin users
function Add-LocalAdminUsers {
    param (
        [string]$UserListPath,
        [SecureString]$SecurePassword
    )
    
    Write-Host "[*] Adding users as local administrators..." -ForegroundColor Cyan
    
    # Read user list
    $Users = Get-Content -Path $UserListPath
    
    foreach ($User in $Users) {
        try {
            # Create the user account if it doesn't exist
            if (-not (Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
                Write-Host "[+] Creating local user: $User" -ForegroundColor Green
                New-LocalUser -Name $User -Password $SecurePassword -FullName $User -Description "Admin User" -AccountNeverExpires -PasswordNeverExpires
            } else {
                Write-Host "[!] User $User already exists" -ForegroundColor Yellow
            }
            
            # Add user to administrators group
            Write-Host "[+] Adding $User to Administrators group" -ForegroundColor Green
            Add-LocalGroupMember -Group "Administrators" -Member $User -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "[!] Error processing user $User`: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "[*] Local user creation complete" -ForegroundColor Cyan
}

# Function to add domain admin users
function Add-DomainAdminUsers {
    param (
        [string]$UserListPath,
        [SecureString]$SecurePassword,
        [string]$DomainName
    )
    
    Write-Host "[*] Adding users as domain administrators..." -ForegroundColor Cyan
    
    # Check if ActiveDirectory module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Host "[!] ActiveDirectory module not found. Please run this on a domain controller or install RSAT tools." -ForegroundColor Red
        return
    }
    
    # Import ActiveDirectory module
    Import-Module ActiveDirectory
    
    # Read user list
    $Users = Get-Content -Path $UserListPath
    $GroupIndex = 0
    
    foreach ($User in $Users) {
        try {
            # Create domain user if it doesn't exist
            if (-not (Get-ADUser -Filter "SamAccountName -eq '$User'" -ErrorAction SilentlyContinue)) {
                Write-Host "[+] Creating domain user: $User" -ForegroundColor Green
                New-ADUser -Name $User -SamAccountName $User -UserPrincipalName "$User@$DomainName" -AccountPassword $SecurePassword -Enabled $true -PasswordNeverExpires $true
            } else {
                Write-Host "[!] Domain user $User already exists" -ForegroundColor Yellow
            }
            
            # Add user to Domain Admins
            Write-Host "[+] Adding $User to Domain Admins group" -ForegroundColor Green
            Add-ADGroupMember -Identity "Domain Admins" -Members $User -ErrorAction SilentlyContinue
            
            # Add to local administrators (requires special handling in domain context)
            Write-Host "[+] Adding $User to local Administrators group" -ForegroundColor Green
            $DomainUser = "$DomainName\$User"
            & net localgroup administrators $DomainUser /add
            
            # Add to one of the privileged groups in a rotating fashion
            $CurrentGroup = $PrivilegedGroups[$GroupIndex]
            Write-Host "[+] Adding $User to $CurrentGroup" -ForegroundColor Green
            Add-ADGroupMember -Identity $CurrentGroup -Members $User -ErrorAction SilentlyContinue
            
            # Increment and wrap around the group index
            $GroupIndex = ($GroupIndex + 1) % $PrivilegedGroups.Count
        }
        catch {
            Write-Host "[!] Error processing domain user $User`: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "[*] Domain user creation complete" -ForegroundColor Cyan
}

# Main execution logic
try {
    if ($Mode -eq "Local") {
        Add-LocalAdminUsers -UserListPath $UserListPath -SecurePassword $SecurePassword
    }
    elseif ($Mode -eq "Domain") {
        Add-DomainAdminUsers -UserListPath $UserListPath -SecurePassword $SecurePassword -DomainName $DomainName
    }
}
catch {
    Write-Host "[!] An error occurred during execution: $_" -ForegroundColor Red
}