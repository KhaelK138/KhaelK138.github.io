

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
    - We can detach from screen with `CTRL A` then `D`, and reattach with `screen -r`, or `CTRL A` then `K` to kill the screen
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
- After we're connected to the chip, we'll use `flashrom` to dump the contents
  - `sudo flashrom -p {programmer} -r {outfile}.bin`
    - `programmer` can be something like `ch341a_spi` for the clip
    - If using raspberry pi, we'd specify `linux_spi:dev=/dev/spidev0.0,spispeed=8000` as the programmer

## I2C
- Used for inter-chip communication
- Has `SDA` and `SCL` pins, using address-based communication
- Logic2 can analyze after identifying the pins


## Misc
- Sometimes, we'll only want to power a section of the board, like a daughterboard