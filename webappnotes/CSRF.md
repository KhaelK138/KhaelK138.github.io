### CSRF

Cause a victim to do an action unintentionally by having them make a request (e.g. `https://example.com/changeemail?email=attacker@email.com`)

CSRF requires:
- An action to induce
- Solely cookie-based session handling (not using SameSite)
  - Can also work with basic auth or cert-based auth
- No unpredictable parameters (like anti-csrf tokens)

SameSite Cookies:
- Strict
  - Never allows cookies to be sent in a cross-site request (iframes, links to other sites, data submission to other sites)
- Lax (default)
  - Sent only on some cross-site requests (clicking on a link or performing GET, HEAD, or OPTIONS request)
    - This means that if data is changed in a GET request (like /email/change?email=attacker@attacker.com), this would still allow CSRF
    - However, this doesn't work for embedded requests (like in images, scripts, or iframes)
- None
  - No restrictions
  - Requires Secure flag (only sent over HTTPS)

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

Common validation issues:
- Switching POST to GET 
  - Can use the PoC above but just remove `method="POST"`
- Omitting the token
  - PoC above as is
- CSRF token not tied to user session (this happened with UT nonce)
  - Just get a token ourselves and add it to the form when submitting
- CSRF token in request data tied to a non-session-tracking cookie, like another CSRF token
  - If this token can be set or predicted by an attacker, they could include or set the relevant attached CSRF token
  - Can sometimes inject cookies through the URL like so:
    - `?search=test%0d%0aSet-Cookie:%20{cookie}={value}%3b%20SameSite=None` if the parameter ends up in the cookies (something like `lastSearch={search_value}`)
  - 
