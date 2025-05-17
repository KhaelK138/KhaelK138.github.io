---
layout: blank
pagetitle: Hacking Bluetooth Low Energy (BLE) Functionality
---

## Bluetooth info
- 2.4GHz frequency
- Is a Frequency-hopping spread spectrum (FHSS)
  - This means that it doesn't just stick to one channel, like WiFi does - BLE hops between 37
- Bluetooth Classic vs BLE
  - Classic has higher power consumption; supports up to 3 Mbps over 80 channels
  - BLE uses less power (duh); supports up to 2 Mbps (alongside 1 Mbps and 500 or 125 Kbps) over 3 advertising channels and 37 data channels
- Controlling device, like a cellphone, is called the "Central" device and Bluetooth device is called "Peripheral" device

## BLE Stack
- Link layer
  - MAC address of client and server devices
  - Encryption is performed at this layer
- Host Controller Interface (HCI)
  - This is where the software interacts with the hardware (implemented usually on the BLE chip)
  - Where packet capture can occur

## BLE Communication
- Peripheral device advertises willingness to connect on 1 of the 3 advertising channels
  - Central device scans on these channels and initiates a connection
- **Characteristics** are basically Bluetooth endpoints
  - For example, on a BLE heart-rate monitor, these could be something like `Heart Rate`, `Battery Service`, or `Generic Access`
  - Each characteristic has its own UUID and permissions (Read, Write, Notify (when a data update occurs))
  - These can be enumerated
- **Encryption**
  - Comms are unencrypted and unauthenticated by default
  - Encryption requires pairing (key exchange between central and peripheral devices)
    - Legacy Pairing (BLE 4.0 and 4.1) is outdated and can be cracked easily with [https://github.com/mikeryan/crackle/](https://github.com/mikeryan/crackle/)
    - Secure Pairing (BLE 4.2+) uses an ECDH-based key exchange, and requires active MITM at pairing to compromise (which is pretty tough)


## Monitoring/Sniffing BLE
**Tools**
- Can use nRF Connect app (both iOS and Android surprisingly) to monitor nearby bluetooth devices
  - Can use [BlueSee](https://apps.apple.com/us/app/bluesee-ble-debugger/id1336679524?mt=12) on Mac
  - Also have nRF Connect for Desktop for PCs
- Other tools used
  - Bluetooth Dongle
    - Just a USB BLE interface to provide bluetooth to an OS (like a VM)
  - nRF52840
    - Microcontroller supporting all BLE 5 features (along with other 2.4Ghz protocols)
    - Can flash firmware to do fuzzing and custom advertising/spoofing
    - NovelBits has a [guide](https://novelbits.io/nordic-ble-sniffer-guide-using-nrf52840-wireshark/) for capturing BLE with Wireshark
  - Ubertooth One (not used that much)
**Packet Captures**
- Capturing BLE packets over the air is unreliable and encrypted, but might be the only option when Central and Peripheral devices aren't under control
- Capturing from a controlled device before encryption is applied is better

## BLE Interaction
- After connecting nRF52840 dongle, we can use it to interact with nearby bluetooth devices via nRF Connect for Desktop Bluetooth Low Energy (downloaded from the nRF Connect for Desktop app)
- Run scan to see devices that the dongle can see, and then we can connect to view the services available (along with their characteristics)


## Miscellaneous
- Tool to lookup first three octets of a MAC address to see who it's from: https://www.wireshark.org/tools/oui-lookup.html
  - For example, `b8:c0:65`, returns `Universal Electronics, Inc.`