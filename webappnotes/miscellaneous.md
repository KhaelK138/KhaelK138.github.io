---
layout: blank
pagetitle: Miscellaneous Web Notes
---


[HackTheBox - Attacking Common Applications](https://academy.hackthebox.com/module/113/section/1087)
[HackTheBox - Attacking Common Services](https://academy.hackthebox.com/module/116/section/1140)

## Enumeration
- Install Wappalyzer
- `gobuster`
	- Enumerates dirs/files; very noisy
	- Usage: `gobuster dir -u {IP} -w /usr/share/wordlists/dirb/common.txt -t {threads}`
	- Make sure it checks for .git
		- https://github.com/arthaud/git-dumper to dump the info
		- https://medium.com/swlh/hacking-git-directories-e0e60fa79a36
- `dirbuster`
  - Has a nice GUI, installed with `apt`
- Check robots.txt
- Check for APIs with /FUZZ/v1 or /FUZZ/v2
- Check for git with `.git`
- Fuzz default IIS servers!!! They can have stuff
- `whatweb` is like a local wappalyzer on kali
	- `whatweb http://{IP}`

## Exploitation
- Finding default passwords for HTTP basic auth
	- Use [LoginHunter](https://github.com/InfosecMatter/default-http-login-hunter) with a list of hosts to find things like cameras w default passwords
	- Can be very useful on internal engagements with hundreds/thousands of webservers
- HTTP Headers:
	- `HTTP User-Agent` can sometimes be displayed in logging pages, so modifying it could XSS or SQLi some sites
	- `Server` response can reveal info about server

## Miscellaneous Tricks
- On password registrations, modify the URL parameter to contain two emails to see what happens
  - For example, change `email=test@test.com` to `email[]=test@test.com,attacker@attacker_server.com`
  - This was the cause of a complete account takeover on gitlab

## Testing SAML
- [https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/](https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/) - great blog post

https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study
https://github.com/DingyShark/BurpSuiteCertifiedPractitioner
https://bscp.guide/

Usernames: https://portswigger.net/web-security/authentication/auth-lab-usernames
Passwords: https://portswigger.net/web-security/authentication/auth-lab-passwords

