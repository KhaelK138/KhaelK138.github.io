---
layout: blank
pagetitle: Android Apps
---

## APKTool
- `apt install apktool`
- `apktool d {apk_file}`

## Static Reversing - JADX
- Use jadx GUI - installable in Kali with `apt install jadx`, pass it the apk file
- Check out the AndroidManifest.xml to see two things:
    - What permission the app requests
    - Entry points to the application (android:enabled="true" or android:exported="true"), browse to the `android.name` in the code
        - This will lead to the starting code, can double click functions within this starting code to see where they are/what they do

## Dynamic Reversing - ADB/Burpsuite
- Use an Emulator - type doesn't matter, maybe use GenyMotion
  - I used Android Studio 
    - You can just drag and drop the apk file on the running device to install the apk
  - Setup:
    - Install Android Studio and run an emulated device
      - Tools below, like Frida and adb, will automatically detect a running device, which is quite nice
    - Install `adb`
    - Use [rootAVD.sh](https://gitlab.com/newbit/rootAVD) on the host machine to root the device
      - Seems the shell script is a bit buggy on Mac, but it works when passing the `ramdisk.img` path within `~/Library/Android/sdk/` (e.g. `system-images/android-34/...`)
    - Then, cold boot the device (trying to boot after rooting causes issues)
- `adb devices` to see devices running
- `adb shell ps | grep -i {app packaging name}` to see running processes
- `adb logcat --pid={process id from above}` to see log messages for application
- BurpSuite can be a pain, but worth it - [https://portswigger.net/burp/documentation/desktop/mobile/config-android-device](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device)
- Telnet
  - Adb will host a port locally that you can telnet to, which supports a lot of different stuff
  - Can be connected to with `telnet 127.0.0.1 {adb_device_id_like_5554}`
  - We authenticate with `auth {value in ~/.emulator_console_auth_token}` and then can interact with the device
  - For example, can control the accelerometer with `sensor status` and `sensor set acceleration 0:9.8:0`

## Drozer
- Great multipurpose tool - [https://labs.reversec.com/tools/drozer](https://labs.reversec.com/tools/drozer)
- Installed with `pipx install drozer`
- Then, download the agent from [https://github.com/WithSecureLabs/drozer-agent](https://github.com/WithSecureLabs/drozer-agent) and install it with `adb install drozer-agent.apk`
  - Then, in the emulator, go to the drozer app and start up the embedded server on port 31415
  - To allow communication on the host, use `adb forward tcp:31415 tcp:31415`
- Then just run `drozer console connect`


## Frida

**Installation**
- Install the toolkit on the host with `pip3 install frida-tools`
- Download the server from [here](https://github.com/frida/frida/releases/latest) 
  - Make absolutely sure the client and server version match
  - On Google Play versions past August 1 2024, Frida is broken it seems
    - Apparently newer versions fixed this, but that doesn't seem to be the case
    - Got adb/frida working on API 29, which DOES have google play store
  - Install on the client with `adb`
    - `adb push {server_file} /data/local/tmp`
    - `adb shell` then `su` (must already be rooted)
    - `chmod +x /data/local/tmp/{server_file}` and `./data/local/tmp/{server_file}`
    - test on host side with `frida-ps -U`
- Can hook functions and change return values to bypass anti-emulators and such

**Dumping process memory with `fridump`**
- [https://github.com/Nightbringer21/fridump](https://github.com/Nightbringer21/fridump)
- Requires that the frida server is running AND the versions match exactly (otherwise the server won't be recognized)
- `python3 fridump.py -U <APP NAME> -s` to dump memory to `./dump`
  - It will also run `strings` on all dumps, saving all strings to `./dump/strings.txt`
- If using API 17+, we can get API issues, but we can fix by editing `fridump.py` and replacing `create_script` with:
```js
script = session.create_script("""'use strict';
 rpc.exports = {
   enumerateRanges: function (prot) {
     return Process.enumerateRanges(prot);
   },
   readMemory: function (address, size) {
     return ptr(address).readByteArray(size);
   }
 };
""")
```

**Modifying Process Memory**
- Can connect to a process by name wit `frida -U -n "{process_name}"`
  - This comes from `frida-ps -U`
  - If we want to connect custom scripts, we can do so with `-l {js_file}.js`
- Then, once inside, we can overwrite process memory with `Memory.writeU32({address}, {newValue})`
- I vibecoded a Frida script that can scan and edit memory, similar to cheat engine: [https://khaelkugler.com/misc_scripts/memscan.js.html](https://khaelkugler.com/misc_scripts/memscan.js.html)
  - Run with `frida -U -n "{process_name}" -l memscan.js`
  - Scan for integers with `msNew({value})`
  - Scan for ranges of floats with `msNewRange({value1}, {value2})`
  - Refine ranges with `msRefine({eq/lt/gt}, {value})`
  - Freeze (constantly overwrite) values with `msFreeze(index)`
