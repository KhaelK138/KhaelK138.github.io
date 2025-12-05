---
layout: blank
pagetitle: External Assessments
---

## Uncovering Assets

**Project Discovery Tools**
- subfinder seems to be the go-to here
  - `subfinder -d {domain} -all`
  - However, [BBOT](https://github.com/blacklanternsecurity/bbot) seems like a good contender to test out for findings subdomains
    - `bbot -t evilcorp.com -p kitchen-sink`
- shuffledns can then be used for DNS brute-forcing
  - `shuffledns -d {domain} -list {subdomain_list} -mode resolve`
- alterx can create permutations of the dns names we find
  - `cat {subdomain_list} | alterx`
- Then we can run dnsx to resolve the permutations
  - `cat {subdomain_list}  | dnsx`
- Then we can use naabu as a port scanner on the subdomains
  - `cat subdomains.txt | naabu -top-ports 100`
- Can then use katana to perform web crawling
  - `katana -u {subdomain} -jc`

[Project Discovery's Tool Manager](https://github.com/projectdiscovery/pdtm) can install all of the above go tools in one shot
- `go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest`

- crt.sh, merklemap.com, censys, Shodan, Gau, Whoxy, LinkedIn scraping, Google Dorks, Crunchbase, Zoominfo

- PHENOMINAL bug bounty/dork search: [https://taksec.github.io/google-dorks-bug-bounty/](https://taksec.github.io/google-dorks-bug-bounty/)
- Awesome censys queries: [https://github.com/thehappydinoa/awesome-censys-queries](https://github.com/thehappydinoa/awesome-censys-queries)

- Neat new domain-based search engine: https://chaos.projectdiscovery.io/

- Burp Enterprise is really good for automatically searching for classic bugs on a list of sites

## Viewing websites:

**GoWitness**
- Run gowitness on the IP ranges/hosts, enumerate mainly the 200s unless there's time for all
  - If we have a list of IPs: `gowitness scan file  --write-db -f {file_with_ips}`
  - If we have a list of CIDRs: `gowitness scan cidr  --write-db --cidr-file {file_with_cidrs}`
- Then just view the results by running `gowitness report server` in the same directory (with `gowitness.sqlite3`)

**EyeBaller**
- Tool from BishopFox, uses machine learning as well for viewing websites

Finding user information and passwords:
- Seems [dehashed](http://dehashed.com/) could be a good tool for enumeration
  - `sudo python3 dehashed.py -q {domain_name} -p`
- [linkedin2username](https://github.com/initstring/linkedin2username) to get corporate usernames

**Shodan**
- Super powerful, has a lot of stuff indexed
- Initialize with `shodan init {API_key}`
- Search with `shodan download --limit 5000 {out_file} "port:37777"`
  - [Searching Cheat Sheet](https://denizhalil.com/2023/12/19/shodan-dork-cheat-sheet/)
  - This will give us a gz json file with lots of data per IP, such as `product`, `ip_str`, and `port`
- We can then filter data with `shodan parse`
  - `shodan parse --fields ip_str,product {out_file}.json.gz`

## Email & Domain security

**Email security**
- [DMARCLY](https://dmarcly.com/tools/) has some great online tools that can check TXT records
- We can also check records ourselves with `host -t txt {domain}` and `host -t a {domain}`

**Subdomain takeovers**
- [baddns](https://github.com/blacklanternsecurity/baddns) seems to be the go-to here
  - `baddns {domain}`
  - Be aware of false positives -- if it doesn't make sense, it's probably not a finding

## Cloud
- [cloud_enum](https://github.com/initstring/cloud_enum) seem to be a fantastic tool
  - `python3 cloud_enum.py -k {keyword_to_search_for} --quickscan`


## Secrets

**OneDrive**
- Can sometimes find o365 users from OneDrive
- [onedrive_user_enum](https://github.com/nyxgeek/onedrive_user_enum) can do this automatically
  - `Semaphore` can cause issues, so `echo "$(grep -v "Semaphore" requirements.txt)" > requirements.txt`
  - Then `python3 onedrive_enum.py -d {domain} (-u {username})`

**Github**
- Worth searching for random projects or in their organizations for information
- Can use noseyparker
  - `noseyparker scan --github-org={org}`

**Documentation/Wikis**
Search documentation/internal wikis for:

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