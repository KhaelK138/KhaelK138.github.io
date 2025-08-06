---
layout: blank
pagetitle: Password Attacks
---

## Hydra
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

## Passwords
- AES is symmetric, RSA is asymmetric
- GPUs crack like a thousand times faster than CPUs

## Finding Passwords
- Just use noseyparker. Can scan file systems, cloned repositories, and even entire github organizations.
    - `noseyparker scan {repo/directory}`
    - `noseyparker scan --github-org={org}`
    - Show results with `noseyparker report`
- Make sure to save or delete the existing `datastore.np` before starting a new scan
- If you want to scan a filesystem that has noseyparker on it, just `chmod 111 noseyparker` before running

## Password Cracking
- Example hashes for each hashcat mode: [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
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

## SSH Private Key Passphrase
- `ssh2john {private RSA SSH key file} > ssh.hash` will put the hash in a crack-able format
- `hashcat -m 22921 ssh.hash {password_list} -r {mutation} --force` will crack the SSH hash
	- 22921 comes from looking up \$6$ in the `hashcat --help` response
	- However, this might result in an error due to this cipher not being supported by hashcat
- John the Ripper 
	- Can handle the error above
	- Can use mutation rules, placed at the end of /etc/john/john.conf
	- `john --wordlist={password_list} --rules=sshRules {hash}` to crack

