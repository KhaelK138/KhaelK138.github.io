---
layout: blank
pagetitle: Android Reverse Engineering
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
    - Seems you can just drag and drop the apk file on the running device to install the apk
  - Setup:
    - Install Android Studio and run an emulated device
      - Tools below, like Frida and adb, will automatically detect a running device, which is quite nice
    - Install `adb`
    - Use [rootAVD.sh](https://gitlab.com/newbit/rootAVD) on the host machine to root the device
- `adb devices` to see devices running
- `adb shell ps | grep -i {app packaging name}` to see running processes
- `adb logcat --pid={process id from above}` to see log messages for application
- BurpSuite can be a pain, but worth it - [https://portswigger.net/burp/documentation/desktop/mobile/config-android-device](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device)

## Drozer
- Great multipurpose tool - [https://labs.withsecure.com/tools/drozer](https://labs.withsecure.com/tools/drozer)
- Installed with `pipx install drozer`
- Then, download the agent from [https://github.com/WithSecureLabs/drozer-agent](https://github.com/WithSecureLabs/drozer-agent) and install it with `adb install drozer-agent.apk`
  - Then, in the emulator, go to the drozer app and start up the embedded server on port 31415
  - To allow communication on the host, use `adb forward tcp:31415 tcp31415`
- Then just run `drozer console connect`


## Frida
- Install the toolkit on the host with `pip3 install frida-tools`
- Download the server from [here](https://github.com/frida/frida/releases/latest) 
  - On Google Play versions past August 1 2024, Frida is broken
    - Run `pm uninstall com.google.android.art` and reboot to fix
  - Install on the client with `adb`
    - `adb push {server_file} /data/local/tmp`
    - `adb shell` then `su` (must already be rooted)
    - `chmod +x /data/local/tmp/{server_file}` and `./data/local/tmp/{server_file}`
- Can hook functions and change return values to bypass anti-emulators and such