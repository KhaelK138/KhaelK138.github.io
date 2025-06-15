---
layout: blank
pagetitle: Miscellaneous Web Notes
---


[HackTheBox - Attacking Common Applications](https://academy.hackthebox.com/module/113/section/1087)
[HackTheBox - Attacking Common Services](https://academy.hackthebox.com/module/116/section/1140)

## Enumeration

**Common Tools**
- `FinalRecon`: A Python-based reconnaissance tool offering a range of modules for different tasks like SSL certificate checking, Whois information gathering, header analysis, and crawling. Its modular structure enables easy customisation for specific needs.
- `Recon-ng`: A powerful framework written in Python that offers a modular structure with various modules for different reconnaissance tasks. It can perform DNS enumeration, subdomain discovery, port scanning, web crawling, and even exploit known vulnerabilities.
- `theHarvester`: Specifically designed for gathering email addresses, subdomains, hosts, employee names, open ports, and banners from different public sources like search engines, PGP key servers, and the SHODAN database. It is a command-line tool written in Python.
- `SpiderFoot`: An open-source intelligence automation tool that integrates with various data sources to collect information about a target, including IP addresses, domain names, email addresses, and social media profiles. It can perform DNS lookups, web crawling, port scanning, and more.
- `OSINT Framework`: A collection of various tools and resources for open-source intelligence gathering. It covers a wide range of information sources, including social media, search engines, public records, and more.
- `Wappalyzer` - will analyze the page in-browser and report back on version numbers
- `Whatweb` -  Like a local Wappalyzer on kali - `whatweb http://{IP}`
- `gobuster`
	- Enumerates dirs/files; very noisy
	- Usage: `gobuster dir -u {IP} -w /usr/share/wordlists/dirb/common.txt -t {threads}`
	- Make sure it checks for .git
		- https://github.com/arthaud/git-dumper to dump the info
		- https://medium.com/swlh/hacking-git-directories-e0e60fa79a36
- `dirbuster`
  - Has a nice GUI, installed with `apt`
- Other notes:
	- Check robots.txt
	- Check for APIs with /FUZZ/v1 or /FUZZ/v2
	- Check for git with `.git`
	- Make sure to fuzz default IIS servers


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

