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

**Misc tools**
- crt.sh, merklemap.com, censys, Shodan, Gau, Whoxy, LinkedIn scraping, Google Dorks, Crunchbase, Zoominfo

**Search tools**
- PHENOMINAL bug bounty/dork search: [https://taksec.github.io/google-dorks-bug-bounty/](https://taksec.github.io/google-dorks-bug-bounty/)
- Awesome censys queries: [https://github.com/thehappydinoa/awesome-censys-queries](https://github.com/thehappydinoa/awesome-censys-queries)
- Neat new domain-based search engine: https://chaos.projectdiscovery.io/

**DNS Querying**
- Often, when performing nmap scans on enormous ranges, we'll need multiple DNS servers to resolve hostnames (so we don't get throttled)
- These can be found with [dnsvalidator](https://github.com/vortexau/dnsvalidator.git)
  - Install with `git clone https://github.com/vortexau/dnsvalidator.git; cd dnsvalidator; python3 setup.py install`
  - Then run `dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -o resolvers.txt`

## Viewing websites:

**EyeWitness**
- Run eyewitness on the IP ranges/hosts to snag pictures of all websites and generate an HTML report
  - It will also enumerate default credentials!!
- Installation: 
  - `git clone https://github.com/RedSiege/EyeWitness.git; cd EyeWitness/setup; sudo ./setup.sh; cd ..; source eyewitness-venv/bin/activate`
- Usage:
  - `python3 Python/EyeWitness.py --web -f {ip_list} --results 200 -d {output_dir} --threads {default_4}`
    - Can remove `--results 200` if we want other results
    - Can add `--only-ports 80,443,8080,8443,5000,3000,8888,8081,7000` if we want a more in-depth scan
  - Resume a scan: `python3 Python/EyeWitness.py --resume {output_dir}/ew.db`
- Then just view the results in the resulting `report.html` file generated in the output directory

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

**Burp**
- Burp Enterprise is really good for automatically searching for classic bugs on a list of sites

## Email & Domain security

**Email security**
- [DMARCLY](https://dmarcly.com/tools/) has some great online tools that can check TXT records
  - We can also check records ourselves with `host -t txt {domain}` and `host -t a {domain}`
- [Spoofy](https://github.com/MattKeeley/Spoofy.git) will check if a domain's emails can be spoofed
  - Then, we can use a site like `https://emkei.cz/` to actually send the spoofed email

**Subdomain takeovers**
- [baddns](https://github.com/blacklanternsecurity/baddns) seems to be the go-to here
  - `baddns {domain}`
  - Be aware of false positives -- if it doesn't make sense, it's probably not a finding

## Cloud
- [cloud_enum](https://github.com/initstring/cloud_enum) seem to be a fantastic tool
  - `python3 cloud_enum.py -k {keyword_to_search_for} --quickscan`

**AADInternals**
- Powershell module used for administering Entra/O365
  - `https://github.com/Gerenios/AADInternals` - `Install-Module AADInternals`, then `Import-Module -Name "AADInternals"`
- `Invoke-AADIntReconAsOutsider -Domain company.com | Format-Table `
  - If we know a username: `Invoke-AADIntReconAsOutsider -UserName "{username}@{domain}" | Format-Table`
  - Username spray with `Get-Content {username_file} | Invoke-AADIntUserEnumerationAsOutsider -Method Login`

## Secrets

**LinkedIn**
- Absolute gold mine for emails, especially when dealing with o365 clients
  - Can simply see the people working under a company, or use something like Phantom Buster for scraping

**O365**
- Can check whether a domain is federated or managed at [https://login.microsoftonline.com/getuserrealm.srf?login={user}@{domain}&xml=1](https://login.microsoftonline.com/getuserrealm.srf?login={user}@{domain}&xml=1)

**Password spraying**
- Can use [AzureAD_Autologon_Brute](https://github.com/nyxgeek/AzureAD_Autologon_Brute) to spray usernames
  - This works if managed, federated, federated w/sso, or on-prem ADFS
- Can use [o365spray](https://github.com/0xZDH/o365spray) to spray credentials for O365 managed tenants
  - `python3 o365spray.py --spray -U {email_list} -p {password_list} --proxy-url {fireproxy_url} -d {domain} --sleep 15 --jitter 30`
  - For federated, target against the URL from the above O365 check
  - For federated w/sso, important to get permission s things like Okta may have zero-reset lockouts
- For on-prem ADFS, use [ADFS Spray](https://github.com/xFreed0m/ADFSpray)
  - Haven't tested it, but `o365spray` does have an `--adfs-url` option

**OneDrive**
- Can sometimes find o365 users from OneDrive
- [onedrive_user_enum](https://github.com/nyxgeek/onedrive_user_enum) can do this automatically
  - `Semaphore` can cause issues, so `echo "$(grep -v "Semaphore" requirements.txt)" > requirements.txt`
  - Then `python3 onedrive_enum.py -d {domain} (-u {username})`

**Github**
- Worth searching for random projects or in their organizations for information
- Can use noseyparker
  - `noseyparker scan --github-org={org}`

**Rotating IPs**
- Often, the identity providers will have brute-force protections in place
- [fireprox](https://github.com/Sprocket-Security/fireproxng) is a pretty good tool to leverage AWS for password spraying
  - Creates a fireprox URL pointing to client login portal (should look like `https://xxxx.execute-api.us-east-1.amazonaws.com/fireprox`)
  - Then just use the fireprox URL as the target of the spraying instead of the actual target
  - Usage:
    - Install `fireproxng` with `pip install fireproxng` and get an AWS API access and secret key
      - Seems later versions of python can't build `lxml`, so we need to do `python3.12 -m venv venv` before installing
      - Might need packages: `sudo apt install -y libxml2-dev libxslt-dev python3-dev build-essential`
    - Create `fireproxng` URL with `fireproxng -ak {access_key} -sk {secret_key} create https://{login_portal}`

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

