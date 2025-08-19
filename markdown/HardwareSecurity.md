

## Basics and Components of Hardware

## Electrical Fundamentals

**Voltage**
- Difference in electric potential between two points
  - Could be thought of as water pressure in two locations, where water will flow from high to low pressure areas
- Pushes current through a circuit, measured in Volts (V)
- Electrons flow through the device from the negative to the positive

**Ground**
- Very important, acts as an unmoving reference
  - Typically the lowest voltage line in a circuit (with exceptions for things like audio processing and motor controls)
- If something is 5V, it's 5V with respect to ground
  - This can differ between devices, so we need to connect the ground of our tools and devices so they have the same reference point

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
