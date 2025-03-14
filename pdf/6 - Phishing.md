

**Techniques:**
- Uses `@` character to tell the browser that everything before the `@` is simply authentication for the following page (an encoded tinyurl site) - I didn't find an arbitrary redirect on github
	- You can't use the `@` technique after a domain AND path have been specified, so specify fake paths using a `/` Unicode lookalike: `∕` (effectively making the TLD in the domain very very long)
	- This lookalike character is a unicode division slash without any numbers (think ⅓)
- You can actually URL encode every single character in a link except for the `/`, so the entire tinyurl link is encoded
- `&` can actually be included without encoding in the authentication information (prior to the `@`), so I included bogus URL parameters from an amazon product link to make it look more realistic (hiding the URL encoded link within)
- For google meets, a link starting with a valid URL (e.g. https://github.com) will be underlined, so I included some hidden unicode characters to break the link

Broken down:
- `https://` - start of URL
- `U+E0001 U+E0020 U+E007F` - hidden Unicode characters to break link underlining functionality in Google meets
- Used https://embracethered.com/blog/ascii-smuggler.html to encode ` `
- `󠁿github.com` - normal github domain
- `∕praetorian-inc∕Cerebrum∕tree∕main∕Personal%20Spaces∕khael.kugler` - realistic path using fake `∕` character
- `&diff=%75%6E%69%66%69%65%64&uuid=259d9f6c-ea4f-492b-a741-8ca016e53a70&ref=main_1598392` - fake URL parameters used to hide the actual payload
- `@%74%69%6E%79%75%72%6C%2E%63%6F%6D/%33%39%74%7A%72%6A%79%6A` - payload decoding to `tinyurl.com/39tzrjyj`, starting with `@`
- `#&whitespace=ignore&inline=false&workflow=ci-deploy-container-ghcr-ref-main` - more fake parameters, starting with a `#` to not confuse tinyurl's redirection

Final payload: https://󠀁󠀠󠁿github.com∕praetorian-inc∕Cerebrum∕tree∕main∕Personal%20Spaces∕khael.kugler&diff=%75%6E%69%66%69%65%64&uuid=259d9f6c-ea4f-492b-a741-8ca016e53a70&ref=main_1598392@%74%69%6E%79%75%72%6C%2E%63%6F%6D/%33%39%74%7A%72%6A%79%6A#&whitespace=ignore&inline=false&workflow=ci-deploy-container-ghcr-ref-main

Other example payloads:
https://github.com∕praetorian-inc∕noseyparker∕releases∕download∕v0.23.0∕secret-noseyparker-v0.23.0-aarch64-apple-darwin.tar.gz&conplccinc=259d9f6c-ea4f-492b-a741-8ca016e53a70ts=abthh8sjiwjcbgqcpkynoq55p8khgag&dasin=B07774L6@%74%69%6E%79%75%72%6C%2E%63%6F%6D/%79%63%38%78%61%66%74%32/&96298722-d186-4e28-b5e9-2ca14f49d977=1

https://www.amazon.com∕gp∕product∕B008A0GNA8pr=conplccinc=259d9f6c-ea4f-492b-a741-8ca016e53a70ts=abthh8sjiwjcbgqcpkynoq55p8khgag&dasin=B07774L6TT&plattr=mathplace=priceblockimp@%74%69%6E%79%75%72%6C%2E%63%6F%6D/%79%63%38%78%61%66%74%32?=96298722-d186-4e28-b5e9-2ca14f49d977

Can also sort of be used to bypass URL validation
Portswigger URL bypass techniques: https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet


