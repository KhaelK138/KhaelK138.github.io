---
layout: blank
pagetitle: Android Reverse Engineering
---

## Static Reversing - JADX
- Use jadx GUI - installable in Kali with `apt install jadx`, pass it the apk file
- Check out the AndroidManifest.xml to see two things:
    - What permission the app requests
    - Entry points to the application (android:enabled="true" or android:exported="true"), browse to the `android.name` in the code
        - This will lead to the starting code, can double click functions within this starting code to see where they are/what they do

## Dynamic Reversing - ADB/Burpsuite
- Use an Emulator - type doesn't matter, maybe use GenyMotion
- `adb devices` to see devices running
- `adb shell ps | grep -i {app packaging name}` to see running processes
- `adb logcat --pid={process id from above}` to see log messages for application
- BurpSuite can be a pain, but worth it - [https://portswigger.net/burp/documentation/desktop/mobile/config-android-device](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device)

## Frida
- Process injection
- Can hook functions and change return values to bypass anti-emulators and such