---
layout: blank
pagetitle: Internal Assessments
---

## Preword

Most internals (at least the ones I've been on) use Active Directory, so refer to those enumeration/exploitation notes for in-depth details on any specific attack path

## Before Credentials Checklist

- [ ] Find domain controllers, usually via DNS
  - [ ] `resolvectl status` can tell us where the upstream DNS servers are
  - [ ] `dig @{DNS_IP} SRV _ldap._tcp.dc._msdcs.{guessed_domain_name}` can show us there the DC SRV records are
    - This might return `NXDOMAIN` but show what the actual domain is, which we can rerun the query against
- [ ] Check domain controller for service issues and common exploits/misconfigs (netexec modules: `ZeroLogon`, `badsuccessor`, `obsolete`, `gpp_password`)
- [ ] Run full nmap scans against the known host subranges
  - [ ] Small UDP scans as well, especially for services like `snmp`, `ike`, and `ipmi` 
  - [ ] Run [gowitness](https://github.com/sensepost/gowitness) against all discovered ports
    - [ ] Run an AI-enabled hunt against all discovered hosts, as AI can very quickly triage for CVEs and default passwords
      - If desired, this can include tools like [LoginHunter](https://github.com/InfosecMatter/default-http-login-hunter) and [Ingram](https://github.com/jorhelp/Ingram)
      - These can often yield LDAP credentials by changing the server they authenticate to
  - [ ] Run a separate AI-enabled hunt against all non-HTTP services (examples described below)
- [ ] Run [Responder](https://github.com/lgandx/Responder) to poison DNS traffic and relay creds to a server without SMB/LDAP protections
- [ ] Run [GetNPUsers](https://github.com/mandiant/gopacket/tree/main/tools/GetNPUsers) to AS-REP Roast users
- [ ] Check for pre-created computer accounts (assigned as pre-Windows 2000 computer) using a tool like [pre2k](https://github.com/garrettfoster13/pre2k)
  - These will have a password of the first 14 characters of the computer name, lowercase (e.g. `dc04-prd-dc1-a`)
  - `nxc`/`impacket` may fail to use these creds (throwing a `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`), so request TGT using creds instead
- [ ] Check for outdated servers susceptible to EternalBlue
- [ ] Timeroast and check for weak (or computer-name) passwords
- [ ] IF CLIENT ALLOWS [mitm6](https://github.com/dirkjanm/mitm6), give it a run to become the DNS server, and then relay auth wherever

**Unauthenticated Service Exploitation**
- FTP/TFTP (21, 69): Check for anonymous logon and ability to write files
- SSH (22, 2222): Check default passwords (if 3rd party device)
- Telnet (23): Check for CVE-2026-24061 - `USER='-f root' telnet -a {IP}`
- CUCM via HTTP (80): Use [SeeYouCM-Thief](https://github.com/trustedsec/SeeYouCM-Thief)
- SNMP (UDP 161/162): Refer to SNMP in Service exploitation notes
- ISAKMP/IKE (UDP 500): Refer to [HackTricks](https://hacktricks.wiki/en/network-services-pentesting/ipsec-ike-vpn-pentesting.html)
- IPMI (UDP 623): Check for IMPI 2.0 auth bypass, anonymous auth, hash dumping 
- Java RMI/JMX (1098, 1099): You can run arbitrary Java code on the host
- NFS (2049): Attempt to mount/write/rootsquash and investigate content for secrets
- Docker REST API (2375/2376): Check for remote container listing and execution
- iSCSI (3260): Remote storage service. Check for anonymous access, mount, scan filesystem for secrets & dump SAM/SYSTEM hashes
- Cisco Smart Install (4786): Use [SIET](https://github.com/frostbits-security/SIET) to exploit CVE-2018–0171
- MySQL/MSSQL/Postgres/OracleDB/AnyDatabase: Check if 3rd party default creds or very weak creds in place (`postgres:postgres`)
- VNC (5900/5901/59000): Check unauthenticated or default pass if 3rd party
- X11 (6000-6063): Refer to [HackTricks](https://hacktricks.wiki/en/network-services-pentesting/6000-pentesting-x11.html), can keylog/view screen

## After Credentials Checklist

- [ ] Run [bloodhound-ce-python](https://github.com/dirkjanm/bloodhound.py) to get a good understanding of the domain and look for the classics
- [ ] Run [Sulla](https://github.com/praetorian-inc/Sulla) to scan for secrets in all SMB shares
- [ ] Run [RelayKing-Depth](https://github.com/depthsecurity/RelayKing-Depth) to scan for general AD misconfigurations and coercion/relay opportunities
  - This will check the domain controllers for missing LDAPS security, which if found, check for NTLMv1, dropthemic, and WebDAV servers
    - Checking DNS options (ADIDNS) & poising is a part of this, so be sure to check that for poisoning options
- [ ] Run [Certipy](https://github.com/ly4k/Certipy) to scan for ADCS issues
- [ ] Run [GetUserSPNs](https://github.com/mandiant/gopacket/tree/main/tools/GetUserSPNs) to kerberoast users
- [ ] Use `querydispinfo` to check each of the users' descriptions for sensitive information
- [ ] AFTER checking domain password/lockout policy and checking with client, perform password spraying with classics
  - If the password policy resets every 15 minutes, then do a spray with one passowrd once every 2 hours
  - `Welcome1, Welcome123, Fall2026! Fall2026, Summer2026, {company_name}123, etc.`
- [ ] Attempt ProxyNotShell against Exchange servers
- [ ] AI-enabled hunt on AD-authenticated web services

## Masscan for larger subnets
- `sudo masscan -iL scope.txt --rate 1000 -oX masscan-sweep.xml -p <ports>`
  - Best with top ports from nmap (and some additional services): `80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,6379,1433,5432,9200,2049`
    - Find other # of top ports: `sort -r -k3 /usr/share/nmap/nmap-services | grep tcp | head -n {num_ports} | awk '{split($2, a, "/"); print a[1]}' | paste -sd ',' -`
      - These can be a bit redundant, so make sure they have what you wanna scan for

## Misc

**Finding subdomains on internal webapps**
- Let's say we have an internal server, like `test.local`
- If we want to find subdomains, `ffuf` can serve us nicely
- Place the IP and `test.local` in `/etc/hosts`, and then run `gobuster vhost -u http://test.local -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 200 --append-domain > vhost` and then grep `vhost` for `"Status: 200"` or `grep -v {data_to_exclude}`
  - Can also try `ffuf -u http://{IP} -H "Host: FUZZ.test.local" -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt`

**Check for Telnet CVE-2026-24061**
- `USER='-f root' telnet -a {IP}`

**Check for IPMI**
- UDP port 623, and will always expose hashes
- Metasploit's `auxiliary/scanner/ipmi/ipmi_dumphashes` can dump the hashes