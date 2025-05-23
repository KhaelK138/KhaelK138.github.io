---
layout: blank
pagetitle: Active Directory Information
---






## ADCS

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