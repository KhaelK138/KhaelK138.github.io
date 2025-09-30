---
layout: blank
pagetitle: Hardware Security
---

## Basics and Components of Hardware

## Electrical Fundamentals

**Voltage**
- Difference in electric potential between two points
  - Could be thought of as water pressure in two locations, where water will flow from high to low pressure areas
- Pushes current through a circuit, measured in Volts (V)
- Electrons flow through the device from the negative to the positive
- This is how data is communicated, via differences in voltage
  - For example, a 1 could be 3.3V and a 0 could be 0V

**Ground**
- Very important, acts as an unmoving reference
  - Typically the lowest voltage line in a circuit (with exceptions for things like audio processing and motor controls)
- If something is 5V, it's 5V with respect to ground
  - This can differ between devices, so we need to connect the ground of our tools and devices so they have the same reference point
  - Look for metal on a board, that'll usually be ground, or sometimes USB connector

**Current**
- Flow of electrical energy from one point to another
  - Like the amount of water flowing through a pipe
- Measured in Amperes (A or I)

**Resistance**
- Opposition to the flow of electric current
  - Like the size of the pipe which water flows through
- Measured in Ohms (Ω)

**Ohm's Law**
- V = I x R

**Power**
- The rate at which energy is transferred
  - Total flow rate of water out of a pipe
- Measured in Watts (W), calculated as P = V x I

**Safety**
- Always power off devices before connecting/disconnecting components
- Make sure to check wires and components for damage
- Work away from water
- Don't short circuits (connect voltage and ground)
- Connect power in proper orientation (check polarity markings)
- Don't connect to wall outlets/high voltage sources
- Don't touch exposed conductors
- Make sure to match voltage levels of tools and items

## Component Identification

- Cheat sheet: [https://www.seeedstudio.com/blog/2019/06/12/12-commonly-used-components-on-pcbs-for-beginners/](https://www.seeedstudio.com/blog/2019/06/12/12-commonly-used-components-on-pcbs-for-beginners/)

**Diodes**
- A type of semi-conductor that's used to control the direction of current
- Like LEDs (light-emitting diodes) or photodiodes, which sense light

**Resistors**
- Limits current flow
- Usually labeled with R
  
**Capacitors**
- Stores energy in electrical potential
- Usually labeled with C
- Resists changes in voltage (if we drop power, they'll slowly discharge, and vice versa)

**Inductors**
- Stores energy in electromagnetic fields
- Resists change in current

**Transistors**
- Semiconductor device used to amplify/switch electrical signals
- Little rectangles with three pins, most commonly 2 on one side and 1 on the other

**Integrated Circuits**
- Can do dedicated tasks, simple or complex
- A little rectangle with lots of pins on each side
- Can do data storage, microcontroller tasks, power regulation, etc.
- We can figure out what it does by matching the shape and searching up the datasheet with the pinout
  - Try to look for datasheets on Digikey or Mouser and not random sus 3rd party sites
    - Not only will they have pinouts, but also pin functions
    - Similarly, we can find the base memory address for flash memory (which we'd like to dump)
  - Use the little circle to orient the chip the same way as shown on the datasheet
  - Sites to search chips by logo: FCCID.io (many corporations must upload information, which we can search by FCC ID), retrosix.wiki, elnec.com, or ecadata.de
    - We can get the FCCID on the board or online (e.g. `{device_name} FCC ID` or `site:{vendor_site} FCC ID`)

**Printed Circuit Boards (PCBs)**
- Fiberglass layer (substrate) with copper on top and then a solder-mask/paintpcb 

**Throughholes**
- Pins that can be accessed from the front and back of the board

**Connectors**
- Sections with pins inside to plug into
- Described based on pitch, which is the distance between the centers of pins (usually 2.54mm)
- Test points - pads used for production programming/validation/troubleshooting
  - Labeled with TP, will look like little exposed copper/tin pads

## Testing a board

**Checking voltages**
- Set multimeter to DC V 20 (to measure up to 20 volts)
  - This is on the left side, AC is on the right (but this will rarely be necessary)
- Then connect black lead (ground) into COM section (common reference AKA ground) and the red lead into the voltage/ohm/amperage section
- Tap the black probe to ground and then use the red probe to check voltages

**Testing continuity**
- Board should not be powered during continuity testing (else we risk shorting the circuit)
- Set the multimeter to the Wifi looking thing
  - This will send current through one of the probes and will check if receiving it through the other probe
- This will tell us if the things we test are connected together
  - For example, we could check to see which pin a test pad is connected to
- Put black cable in COM and red cable in the voltage/ohm/amperage section
- Then touch probes to two locations
- We might have to 

## UART

- Universal Asynchronous Receiver-Transmitter
- Hardware communication protocol allowing serial data exchange between devices without a shared clock signal (done via a Baud rate)
- Active-high vs. active-low:
  - Active-high - idling at 0V and sending data at higher voltage
  - Active-low - idling at higher voltage and sending data at 0V

**Identification**
- 3 pins, ground, Receive, and Transmit, indicate UART
  - Sometimes a 4th pin, Vcc
- When connecting devices, Rx goes to Tx and Tx goes to Rx
  - One device transmits data and the other receives data
  - These can often be mislabeled, so often when debugging first step is to swap these
- Frame:
  - Start bit, data bits, parity bit, and 1-2 required stop bits
  - Data is usually 8 bits, with least significant bit sent first
- Can figure out Rx and Tx by tracing pins to the chip and checking the pinout
  - We can also just connect it to the logic analyzer and see where the data comes from (all data out will come from the board's Tx pin)
- Baud rate is a predefined speed of data measured in bits per second
  - Common values: 115.2k, 9.6k (90% of baud rates), 57.6k, 19.2k, 4.8k
  - Generally running through these 5 will result in a good chance of talking to the device
  - Can also perform a measurement with a logic analyzer and calculate the baud rate 
    - https://github.com/devttys0/baudrate/blob/master/baudrate.py
- Parity start/stop bit is configured to off (99% of the time), even, or odd
- Either 1 or 2 stop bits

**Reading data**
- Use a logic analyzer to connect to the pins
- Connect either ground pin to ground
- Take other two TX/RX and connect to channel 0 and 1
- Open up [Logic2 application](https://www.saleae.com/pages/downloads) to view the data
  - Hovering over the "smallest slice" in Logic2 will show us the baud rate, given by the `width`
  - Settings in the top right to configure if we get buffer errors and such
- Move to analyzer tab (2nd on right side) and select `Async Serial`
  - Enter baud rate, channel with activity, and guess the scheme (usually 8bits, no parity, 1 stop bit)
  - After saving, we can view the hex data above the captured data
    - Right click data and change to ASCII to read plaintext
- This is better for signal analysis, rather than something like UART to USB

**Interacting with UART**
- Can vary wildly based on tools
  - USB to UART is pretty standard - hook it up and then use `screen /dev/ttyUSB0 {baud_rate}` to receive the data
    - We can detach from screen with `CTRL a` then `d`, and reattach with `screen -r`, or `CTRL A` then `K` to kill the screen
  - Using PiFex - Connect board Tx to PiFex IO15 | RX | TCK, Rx to IO14 | TX | TMS, and GND to GND
    - Then, connect with `screen /dev/ttyS0 {baud_rate}`
- Might initially show an empty window, but we can try sending data blindly or power cycling/resetting the device
- If we get hit with an auth page, we can use `pyserial` to try and brute force over a serial connection

## SPI

**Information**
- Serial Peripheral Interface
  - Very common with flash memory chips, sensors, displays, and SD cards
- Characteristics:
  - Synchronous - clock signal is shared and controlled by the controller device
  - Controller/peripheral architecture - single controller with multiple peripherals
  - No frame structure - transmits data without start/stop/parity

**Using SPI**
- No spec for SPI, so each device has implementation details
  - Datasheet will contain implementation details
  - Watch for the Clock Polarity (CPOL) and Clock Phase (CPHA)
    - These describe when lines should be sampled/toggled
    - Quite often mode 0, where polarity and phase are set to 0
      - Worst-case, these can be brute-forced (only four combinations between 00, 01, 10, and 11)
- Will usually not have a pinout, so we use pcbytes kits or micrograbbers to create a pin out
  - We can also use a SOIC clip to try and clip onto a flash chip
- Is a bus, so multiple devices can use the same shared wires
  - SCK - shared clock
  - MOSI/COPI (master-out slave-in/central-out peripheral-in)
    - Essentially transmit from the controller
    - We'll see a request coming from the controller on this line
  - MISO/CIPO (master-in slave-out/central-in peripheral-out)
    - Essentially receive on the controller
    - We'll see the peripheral device's response to the controller's request on this line
- Multiple peripherals are handled by multiple chip select (CS) lines
  - Can also be called slave select lines (SS)
  - These are not shared between peripherals, controller will send out an active low signal over CS lines to signify when it's a peripheral's turn to discuss

**Analyzing SPI on a Logic Analyzer**
- We'll have to zoom in pretty far, since it's a very fast protocol
- Look for challenge response to identify MISO/MOSI, but sometimes it could just be the controller sending data
  - This would be pretty common when sending data to flash, for example
- Choose `SPI` in analysis, set MOSI/MISO/Clock channels, set `polarity`/`phase` to 0, and data should be shown

**Using the CH341a, SPI SOIC-8 clip, and Raspberry pi**
- Pinout is super common, CH341a/SOIC-8 clip will assume it
- SOIC-8 red wire is pin 1, which is the CS pin. Make sure red wire lines up pin 1 on both the chip itself and on the CH341A
  - Half circle on right side of CH341A will show which set of 8 has pin 1 - then we just set it up so the numbers are facing the front of the stick
- Then plug into raspberry pi and do below

**Extracting SPI Flash Memory**
- Peripherals don't usually verify controller authenticity
- Since we have datasheets, we can often just talk to the flash chips directly
  - Will usually use the same pinout as SPI
  - Need to be careful about voltages necessary, as we can easily fry the chip giving 5V to a 3.3V chip
- Sometimes, the controller can try to talk to the flash as the same time as us
  - We can attempt to hold the controller in reset or wait until the controller isn't talking
    - Can just hold the reset button the entire time, but dumping could be very slow, so this isn't smart
    - Instead, we can connect the microcontroller's reset pin to ground or 3.3V
  - Alternatively, we can attempt to remove and resolder the SPI flash
  - Also, we can often run into bit corruptions
    - Thus, dump three times and hash until we have a match
      - `sha256sum *.bin`
- After we're connected to the chip, we'll use `flashrom` to dump the contents
  - `sudo flashrom -p {programmer} -r {outfile}.bin`
    - `programmer` can be something like `ch341a_spi` for the clip
      - Run `-h` for examples
    - If using raspberry pi instead of CH341A, we'd specify `linux_spi:dev=/dev/spidev0.0,spispeed=8000` as the programmer
- Then, we can just `xxd {bin_file} | head -n {lines_to_output}` to read it

**I2C**
- Used for inter-chip communication
- Has `SDA` and `SCL` pins, using address-based communication
- Logic2 can analyze after identifying the pins

## Using/Exploiting Debug Interfaces
- These aid engineers during development and should not be present in production
- Common ones are JTAG/SWD, and sometimes UART

**SWD/JTAG**
- Core capabilities: halt/resume execution, memory read/write, registry manipulation, hardware breakpoint management, and access to real-time variables
- Can be used to bypass security checks, memory exploration, and dumping firmware
- Will usually be either JTAG or SWD on a board

**SWD Overview**
- ARM Serial Wire Debug protocol
- SWDIO (data input/output) and SWCLK (clock) signals
- Debug Access Port (DAP architecture)
- Connect `GND` to `GND` on the pi, `3.3` to `3.3`, `SWDCLK` to `IO9|SDI|SCLK`, `SWDIO` to `IO11|CLK|SWDIO`
- Then, run `sudo openocd -f raspberrypi-native.cfg-swd -f stm32f1x.cgf`
  - These config files come from [https://github.com/openocd-org/openocd/tree/master/tcl/target](https://github.com/openocd-org/openocd/tree/master/tcl/target), but we'll need to edit them a bit to set the correct pins. See [here](https://voidstarsec.com/blog/brushing-up-part-3) for info
- We can then connect via telnet to `localhost 4444`, after which we can perform lots of actions
  - Dump memory with `dump_image {out_file}.bin {starting_address_of_flash} {number_of_bytes_to_dump}`
    - We can find where internal flash memory is based on the microcontroller's datasheet
  - Then grep/strings for interesting info

**Joint Test Action Group (JTAG) Overview**
- Signals: TCK (test clock), TMS (test mode select), TDI (test data in), TDO (test data out)
- Lots of different pinouts (usually 2x4 to 2x10)
  - Can also look for a cluster of test pads with 4 and 4 pins around it, as this is very indicative of tag connect
    - They've removed the headers but they have cables that can press down and connect
- State machine under the hood
  - We start in a reset mode, and every clock cycle we check our `TMS` pin value. If it's 1, we stay, but if it's 0, we move to `run test idle`
  - The rest of JTAG works like this

**Interacting with JTAG**
- Make sure to figure out the pinout first
  - Connect ground to ground, 3.3 to 3.3, and then figure out if any of the other JTAG pins are 3.3 or ground before brute-forcing
  - [go-jtagenum](https://github.com/gremwell/go-jtagenum) is a good tool for bruteforcing 
    - Connect ground, then connect the rest of the pins to all the IO pins, and then run the tool with each of the pins mapped
    - `go-jtagenum -pins '{ "io2": 2, "io3": 3, "io14": 14, {etc.}}' -command scan_idcode -delay-tck 50`
      - Then do `-command scan_bypass` with no `delay-tck` to double check what each of the pins can be
  - JTAGulator is also pretty good for this
- A debugger is the best for interacting with JTAG, such as Segger Jlink (but that's pretty expensive)
  - GDB/OpenOCD can be good
- For hardware interaction, can use JTAG adapters, Pifex, or Bus Pirate
- Connect GND to GND, 3.3V to 3.3V, `IO2 | SDA | TDI` on pifex to `TDI`, `IO3 | SCL | TDO` to `TDO`, `IO14 | TX | TMS` to `TMS`, and `IO15 | RX | |TCK` to `TCK` on board
- We can then run `openocd` command to dump
  - `sudo openocd -f raspberrypi-native.cfg-swd -f stm32f1x.cfg`
    - This is a pretty common config file
      - If on a pi, we may need to use `sysfsgpio-raspberrypi.cfg` as the config file due to some linux kernel shit
  - We can then `telnet` into the locally-opened port on `4444` to access the shell
  - Should immediately run `halt` after getting into the shell
- Getting the initial memory address from the datasheet is really important, as we can use it to dump
  - `dump_image internal.bin 0x0{starting_address} 30000`
    - 30000 is a good number for dumping
  - Then, do it again and compare the hashes

**Debugging with JTAG**
- Run `halt` inside the `4444` service opened by `openocd`
  - This will halt execution and put us in debug-mode
- `reg` to view registers
- Back on the pi, we can use `gdb-multiarch` for a gdb session to step through execution
  - We can then use `openocd`'s gdb service, which is hosted locally on `3333`
    - Run `target remote 127.0.0.1:3333` within GDB
      - To continue execution (after setting desired breakpoints from Ghidra) we should continue, or `c`
      - Then, once we hit our breakpoint, we can read/set memory as necessary and such
  - Then, since we aren't debugging an executable, we'll need to use memory addresses
    - Referring back to the datasheet, we know internal flash starts at `0x08000000`
      - We can dump 30000 bytes starting there into a binary file, and have Ghidra analyze it
- Ghidra process:
  - Import the bin file, and select the architecture of the chip
    - For example, `ARM:LE:32:Cortex:default`
  - Don't analyze it yet, as we need to set the base address
    - Go to Window -> Memory Map
    - Click the home icon in the top right
    - Set the base address
  - Now we can analyze the bin file
    - Go to Analysis -> Auto-analyze
  - Profit!

**JTAG and UART at the Same Time**
- Since they use overlapping pins on the pifex (namely IO14 and IO15), we can move them around
- Still use UART `RX` -> `IO14 TX` and `TX` -> `IO15 RX` on the board
- Move JTAG `TCK` to `IO10` and `TMS` to `IO9`
  - Then need to edit `sysfsgpio-raspberrypi.cfg` to modify remapped pins
    - Change `sysfsgpio jtag_nums 15 14 2 3` to `sysfsgpio jtag_nums 10 9 2 3`

**JTAG protection mechanisms**
- Fuse bits and lock bits
  - Physical fuse within the chip
  - Apply a voltage between two pins for a certain amount of time, which will blow a fuse and disable JTAG
  - This is a pretty good control
- Read-out protection levels
  - Have RDP levels, such as 0, where everything is accessible, and gets less accessible up to level 2
  - Can be glitched down
- Debug interface disable methods
  - Software-level methods to disable results for interacting with debugging interface
  - Different for each vendor, but can be broken depending on implementation

## Firmware Analysis

**Binwalk Analysis**
- Common FS formats: SquashFS, JFFS2, ext4, and UBIFS
  - There are custom tools to extract the files, but binwalk can do it automatically
  - If we want to do it ourselves, find the header and size and use `dd`
- Once inside, want to check for:
  - Debug info: `/sys`, `/proc`, `/dev`, `/debug`
  - Logs: `/var/log`, `/tmp/log`, `/logs`, `/data/logs`
  - Update files: `/tmp/update`, `/mnt/flash`, `/firmware`, `/factory`, `/backup`
  - Update scripts: `/bin`, `/sbin`, `/usr/local/bin`, `/usr/sbin`
  - Network configurations: `/etc/network/interfaces`, `/etc/wpa_supplicant.conf`, `/etc/hostapd.conf`, `/etc/dnsmasq.conf`, `/etc/hosts`
  - Look for passwords to crack (`/etc/shadow`, `/etc/ssl/certs`, `/etc/ssl/private`, `/etc/keys`)
  - Initialization scripts in `/etc/init.d`

**Firmware Manipulation**
- Tools like firmware analysis toolkit can unpack/repack firmware
- Can also do firmware emulation 

**Reflashing**
- Get another session and write to memory rather than reading
- On RTOS, will need to repackage changes back into the initial format (e.g. packing a filesystem back into SquashFS)
  - Flashrom can handle reflashing
- Reflashing can occur via UART, SPI, JTAG, USB, or even over-the-air (OTA) methods

## Misc
- Sometimes, we'll only want to power a section of the board, like a daughterboard