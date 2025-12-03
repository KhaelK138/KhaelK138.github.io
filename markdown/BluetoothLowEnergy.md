---
layout: blank
pagetitle: Hacking Bluetooth Low Energy (BLE) Functionality
---

## BLE Stack
- **RF Protocol** 
  - Physical layer is wireless in ISM band in 2.4 GHz range (2400 MHz thru 2483.5 MHz)
  - 40 Channels; basically 1-39 except 37 is at 2.400, 38 is around 2.425 with 39 at 2.480
  - Each channel has 1 MHz bandwidth and 2MHz spacing between channels
  - Channels 37-39 for advertising
  - Frequency Hopping Spread Spectrum at a specific timing to reduce interference
  - Transmit power from -20dBm (0.01 mW) to +20dBm (100mW)
- **Link layer**
  - On hardware, there's transistor logic that handles some stuff
  - There's also a mix of software that can be installed that handles other stuff (instruction sets)
  - Seven states
    - Standby, advertising, scanning active, scanning passive, initiating, connection (master), connection (slave)
  - Encryption sometimes handled here using AES-138
- **Host Controller Interface (HCI)**
  - Transports commands/events between host and controller components (previous layers of stack)
    - This is what would say "we need to send 8 bytes over this channel"
  - Can be exposed as a software API
  - May appear as SPI or UART
- **Logical Link Control & Adaptation (L2CAP)**
  - Lowest layer on host
  - Responsible for protocol multiplexing, segmentation, reassembly of data exchanged between host and controller
  - Channel based, each endpoint has a channel identifier (CID)
    - GATT protocol uses channel 0x0004
  - Defines Packet Data Units, Max Transmission Unit (MTU), Maximum Packet Size for RF broadcast
    - Every device must support 20 bytes; larger MTU support optional but not guaranteed
  - Gives packets a L2CAP header providing metadata
- **GAP Security Manager (SMP)**
  - Enforces security by any means of encryption
  - Mode 1 Level 1 is the default
  - Security Mode 1:
    - 4 levels of security in this mode:
      - Level 1: No auth or encryption
      - Level 2: Unauthenticated pairing with encryption
      - Level 3: Authenticated pairing with encryption
      - Level 4: Authenticated LE Secure Connections pairing with encryption
    - Levels 3 and 4 are protected against MITM (Level 4 is recommended for secure connections)
  - Security Mode 2: 
    - Much rarer, uses data signing (but not encryption)
      - Useful for integrity but chip can't support encryption
    - 2 levels:
      - Unauthenticated pairing with data signing
      - Authenticated pairing with data signing
  - Security Mode 3:
    - Isochronous data that is specifically meant to be broadcasted 
    - Used with BLE audio
  - Mode 1 levels 1-3 allow Legacy Pairing
    - Generate a 128 bit temporary key used to generate a short term key used to encrypt the link
    - Can be cracked easily with crackle - [https://github.com/mikeryan/crackle/](https://github.com/mikeryan/crackle/)
  - LE Secure connections
    - Uses Elliptic-Curve Diffie-Hellman (ECDH) cryptography to generate a public-private key pair. Devices exchange public keys to generate shared Long Term Key
      - Can be MITM'd during the VERY first connection due to the reusing of the shared Long Term Key
    - Bonding is storing a Long Term Key so you can connect again using the same key
  - **All connections start lifetimes in Mode 1 Level 1**
    - Can be later upgraded to any security level by means of pairing/authentication
      - Passkey Display - One device displays a random six-digit passkey and the other side enters it
      - Out of Band (OOB) - Uses additional information transferred by other means (QR code, NFC, magnetic) alongside public key to generate LTK
        - Using this with Mode 1 Level 4 is the most secure
      - Numeric Comparison - comparison of generated numeric values, and thus MITM won't work unless unmatched values are accepted
- **Generic Access Profile (GAP)**
  - Base of the BLE control plane
  - Discover/connect with peers, broadcast data, establish secure connections using SMP
  - GAP basic roles:
    - Central - scans and initiates connections with peripherals
    - Peripheral - advertises and accepts connections from centrals
    - Broadcaster - peripheral device broadcasting advertisement packets without accepting connections (fails to finish handshake)
    - Observer - central device that doesn't try to initiate a connection
  - A device can have multiple GAP roles at once (peripheral to some devices, central to others)
  - GAP discovery process
    - Advertising
      - Device announces presence with some limited information
    - Scanning
      - Collecting/listening for advertisements
      - May request additional information via a scan request (called scanning a device)
- **Attribute Protocol**
  - Defines additional roles and formats for data access 
  - Devices can be either server or client in a server/client architecture
  - Handles range from 0x0000-0xFFFF
  - GATT server (level 0) builds on top of it with services (level 1), characteristics (level 2), and values/descriptors (level 3)
    - Services are like categories of characteristics, whereas the characteristics themselves can be interacted with
      - For example, there could be a device information service, with characteristics like manufacturer name, firmware version, etc.
  - Characteristics are like APIs that hold a value

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

## Enumerating BLE
- [Bettercap](https://www.bettercap.org/project/introduction/) is almost always the best choice here
  - I've had quite a few issues attempting to install it on a pi; would recommend the docker route (`docker run -it --privileged --net=host --platform linux/arm64 bettercap/bettercap`)
  - Unsupported on Mac/Windows, so necessary to use some linux machine (or Kali VM with connected BLE dongle) of some kind
- Turn on with `ble.recon on` (make sure we have a usable BLE dongle/device with `sudo hciconfig`)
- Recon:
  - `ble.show` to show discovered BLE devices
    - `ble.clear` to clear cached devices collected
  - `ble.enum {MAC}` to enumerate services and characteristics for a given device
    - This will give us a nice table on the device, after which we can turn `ble.recon off`
  - `ble.write {MAC} {characteristic_uuid} {hex}` to write hex data to a device's characteristic

**Hciconfig**
- `sudo hciconfig` to show the connected devices, and note down the identifier
- Bring a device online with `sudo hciconfig {device} up`
  - Then recheck to make sure it's `UP` and `RUNNING`

**Hcitool**
- `sudo hcitool lescan`
- List nearby devices that we can see 
  - Smart to remove "unknown" and known devices using `grep` from this output
- From this, we can grab the MAC address

**Gatttool**
- Useful for reading/writing specific data
- Reading: `gatttool -i {hci_interface} -b {MAC} --char-read -a {service_hex} | awk -F':' '{print $2}'|tr -d ' '| xxd -r -p;printf '\b'`
  - To write, use `--char-write-req -a {service_hex}`

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
      - Follow guide [here](https://wiki.makerdiary.com/nrf52840-mdk-usb-dongle/guides/ble-sniffer/installation/), use [this](https://github.com/makerdiary/nrf52840-mdk-usb-dongle/tree/main/firmware/ble_sniffer)
    - Makerdiary has a guide for sniffing using Wireshark [here](https://wiki.makerdiary.com/nrf52840-mdk-usb-dongle/guides/ble-sniffer/installation/#installing-the-nrf-sniffer-capture-tool)
    - Then, in Wireshark, we can watch BLE traffic
      - To filter for advertising, use `btle.advertising_address == {MAC}` (or `btle.scanning_address`)
      - For actual communication, use `bthci_acl.src.bd_addr == {MAC} || bthci_acl.dst.bd_addr == {MAC}`
  - Ubertooth One (not used that much)

**Packet Captures**
- Capturing BLE packets over the air is unreliable and encrypted, but might be the only option when Central and Peripheral devices aren't under control
- Capturing from a controlled device before encryption is applied is better

## BLE Interaction
- After connecting nRF52840 dongle, we can use it to interact with nearby bluetooth devices via nRF Connect for Desktop Bluetooth Low Energy (downloaded from the nRF Connect for Desktop app)
- Run scan to see devices that the dongle can see, and then we can connect to view the services available (along with their characteristics)

**Bleak**
- General multipurpose BLE tool, available [here](https://github.com/hbldh/bleak)
- This is a great python tool for engagement testing, especially scripting
- Easy to install with `pip install bleak`
  - Examples for scanning/reading in the repo

**Spoofing**
- `bluez` is the Bluetooth/BLE stack for linux
- Easy to interact with it using `bluetoothctl`
- Advertising a device:
  - Try to use nRFconnect with an nRF52840 if possible. The app is a lot easier to use and doesn't give headaches like bluetoothctl
    - After connecting to a device connected via USB, we can set the GATT information in the `Server Setup` page
    - In terms of advertising data, we can set `Manufacturer Data` with a custom AD type of `0xFF` and then passing data in little-endian format
      - Other data, like services (which is `0x03` AD type) can be looked up
  - `bluetoothctl` and `power on`
  - Access advertise menu with `menu advertise`
    - `manufacturer 0x{2_byte_manufacturer_name} 0x{1st_byte_info} 0x{2nd_byte_info}` to set the manufacturer information
      - This seems to cause many issues with bluez, so try `sudo /etc/init.d/bluetooth restart` if failing
    - `name {device_name}` to set the device name
    - `back` to leave the advertising menu
    - `uuids 0x{hexdata_uuid1} 0x{hexdata_uuid2}` to advertise services (naming convention is a bit weird it seems)
    - `service 0x{hexdata_uuid} {service_info_bytesadvertis}` to advertise service data
  - `advertise on` to start advertising
- Adding services/characteristics:
  - `menu gatt` to get to the gatt menu
    - `register-service {128_bit_hex_UUID}`
    - `register-characteristic 0x{hex_UUID_like_1111} {read,write,notify}` 
    - `register-application` to tell BlueZ about the service/characteristics

**MITM tools**
- Seems [ESP32-Gattacker](https://github.com/p0px/ESP32-Gattacker) is the go-to here
- [Gattacker](https://github.com/securing/gattacker) and [BTLEjuice](https://github.com/DigitalSecurity/btlejuice) are the classic tools
  - These are pretty outdated, though

## Miscellaneous
- If using VMWare, uncheck `Share Bluetooth devices with Linux` (somewhat unexpectedly) allowing us to see the BLE dongles as USB devices
- Tool to lookup first three octets of a MAC address to see who it's from: https://www.wireshark.org/tools/oui-lookup.html
  - For example, `b8:c0:65`, returns `Universal Electronics, Inc.`
- [ble_ctf](https://github.com/hackgnar/ble_ctf) is a BLE CTF installed on the ESP32; good practice
- Nordic Security has a DevAcademy with a BLE fundamentals short course (https://academy.nordicsemi.com/courses/bluetooth-low-energy-fundamentals/)