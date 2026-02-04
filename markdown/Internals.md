---
layout: blank
pagetitle: Internal Assessments
---

## Active Directory
- Most of internals (at least the ones I've been on) use Active Directory, so refer to those enumeration/exploitation notes instead

## General scanning
- Nessus is pretty great for identifying a LOT of low hanging fruit, but can be pretty slow if given `/16`s
  - Thus, use `masscan` to identify hosts first, passing these into Nessus
- Installation:

```sh
wget https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-latest-debian10_amd64.deb
sudo dpkg -i Nessus-latest-debian10_amd64.deb
sudo systemctl enable nessusd.service
sudo systemctl start nessusd
```
- Will be accessible at localhost:8834
- Enable web app crawling with pages at 20 and depth at 2

## Masscan
- `sudo masscan -iL scope.txt --rate 1000 -oX masscan-sweep.xml -p <ports>`
  - Best with top ports from nmap (and some additional services): `80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,6379,1433,5432,9200,2049`
    - Find other # of top ports: `sort -r -k3 /usr/share/nmap/nmap-services | grep tcp | head -n {num_ports} | awk '{split($2, a, "/"); print a[1]}' | paste -sd ',' -`
      - These can be a bit redundant, so make sure they have what you wanna scan for

## Webservers
- Run gowitness on the IP ranges, enumerate mainly the 200s unless there's time for all
- `gowitness scan cidr --write-db --cidr {IP_range} --write-db`
  - If we have a list of IPs: `gowitness scan file  --write-db -f {file_with_ips}`
  - If we have a list of CIDRs: `gowitness scan cidr  --write-db --cidr-file {file_with_cidrs}`
- Then just view the results by running `gowitness report server` in the same directory (with `gowitness.sqlite3`)

**Common Passowrds**
- Finding default passwords for HTTP basic auth can be a pretty good first step
	- Use [LoginHunter](https://github.com/InfosecMatter/default-http-login-hunter) with a list of hosts to find servers with default passwords
  - [Ingram](https://github.com/jorhelp/Ingram) is a pretty solid tool for vuln/pass scanning on CCTV

## Finding internal subdomains
- Let's say we have an internal server, like `test.local`
- If we want to find subdomains, `ffuf` can serve us nicely
- Place the IP and `test.local` in `/etc/hosts`, and then run `ffuf -u http://{IP} -H "Host: FUZZ.test.local" -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt`
  - Can also try `gobuster vhost -u http://test.local -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 200 --append-domain > vhost` and then grep `vhost` for `"Status: 200"` or `grep -v {data_to_exclude}`

