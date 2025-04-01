---
layout: blank
pagetitle: Websockets
---

**Common vulnerabilities**
- Since websockets are just another way of communicating with a webserver, most standard vulnerabilities still apply
- Burp's websocket history and repeater can handle websocket communication

**Manipulating Websocket Handshake**
- Process of manipulating the handshake:
  - Send Websocket message to repeater
  - Click pencil next to URL
  - Choose `clone` for a connected websocket or `reconnect` for a disconnected websocket
    - This will show the details of the handshake request, which can be modified
  - Click `connect` to test out the configured handshake
- Common handshake vulnerabilities:
  - Misplaced trust in HTTP headers for security decisions, like `X-Forwarded-For` or any custom headers
    - `X-Forwarded-For` can sometimes bypass IP restrictions
  - Common session-handling mechanism flaws in the handshake

**Cross-site WebSocket Hijacking**
- Results from cross-domain WebSocket connections from an attacker-controlled site