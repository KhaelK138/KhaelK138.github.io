---
layout: blank
pagetitle: iOS Apps
---

## Corellium
- Basically the go-to tool for testing apps, as it can provide an emulated rooted iphone
- Connecting via USB to an emulated Corellium device:
  - Install their OVPN client and connect using [Viscosity VPN Client](https://www.sparklabs.com/viscosity/download/)
    - Need to use this or tunnelblick since they support TAP mode vpn configurations
  - Install and run [USBFlux](https://support.corellium.com/files/USBFlux-1.2.3-5648c71515afa73d9dc932675b6fe0a1b8f704ba.dmg)
    - This will allow connecting to USB devices over the network (VPN)
- Now, we should be able to use tools like `frida` (installation described in Android Apps notes)

**Fridump with Corellium**
- They show a pretty good walkthrough: [https://support.corellium.com/features/frida/fridump-with-corellium](https://support.corellium.com/features/frida/fridump-with-corellium)
- Has the prerequisites of having frida installed MATCHING version on device, being on the vpn, and having USBFlux downloaded and connected
- Then just `python3 fridump.py -U -s '{app name}'`