---
layout: blank
pagetitle: External Assessments
---


Uncovering assets:
- crt.sh, merklemap.com, censys, Shodan, Gau, Whoxy, LinkedIn scraping, Google Dorks, Crunchbase, Zoominfo (zoomeye?)

- PHENOMINAL bug bounty/dork search: https://taksec.github.io/google-dorks-bug-bounty/
- Bug bounty/dorking search engine: https://nitinyadav00.github.io/Bug-Bounty-Search-Engine/
- Awesome censys queries: https://github.com/thehappydinoa/awesome-censys-queries

- Burp Enterprise is really good for automatically searching for classic bugs on a list of sites

Viewing websites:
- Run gowitness on the IP ranges/hosts, enumerate mainly the 200s unless there's time for all
- `gowitness scan cidr --write-db --cidr {IP_range} --write-db`
  - If we have a list of IPs: `gowitness scan file  --write-db -f {file_with_ips}`
  - If we have a list of CIDRs: `gowitness scan cidr  --write-db --cidr-file {file_with_cidrs}`
- Then just view the results by running `gowitness report server` in the same directory (with `gowitness.sqlite3`)

Search documentation/internal resources for:

```
net use
psexec
.pfx
AsPlainText
Authorization: Basic
Authorization: Bearer
NetworkCredential
password
root
passwd
credential
putty
logins
connectionstring
securestring
samaccountname
ldap
sudo
scp
ssh
.vmd
clientdomain\
@clientdomain.com
id_dsa
id_rsa
ghp_
AWS_SECRET_ACCESS_KEY + AKIA/ASIA
ssh_password
net user
```