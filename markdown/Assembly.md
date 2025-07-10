---
layout: blank
pagetitle: Assembly
---

## Assembly Notes

**High-level vs. Low-level**
- Languages have different levels of how close they are to machine code
- Assembly is very close, naturally
  - `add rax, 1` -> `4883C001` -> `01001000 10000011 11000000 00000001`
- Whereas Python is a few more steps away
  - `print("Hello World!")` -> `write(1, "Hello World!", 12);_exit(0);` (C) -> `mov rax, 1; mov rdi, 1; mov rsi, "Hello World!", {etc}` -> shellcode -> binary

**Architecture**
- Memory contains the cache and RAM
  - Cache has between 3 levels, with L1 being the smallest/fastest but closest to the CPU
  - 32 bit systems have addresses between 0x00000000 and 0xffffffff, whereas 64 bit infra goes up to 0xffffffffffffffff
  - RAM is split into 4 parts
    - Stack - LIFO design, data accessed only by pushing/popping data
    - Heap - hierarchical design; larger and better for storing complex data; can be retrieved in any order (but slower as a result)
    - Data - used for variable storage (along with a `.bss` section for unassigned variables)
    - Text - where assembly is loaded into and executed by the CPU
- I/O
  - Processes can control/access I/O via Bus Interfaces
    - Buses have capacities of up to 128 bits
- Storage
  - Slowest form of storage, but can be as large as needed
  - Used to be magnetic drives but shifting to SSDs as they have a similar design to RAM
- CPU
  - Contains ALU, which performs the arithmetic/logical calculations
  - Has a Clock speed and cycle
    - Each tick of the clock processes a basic instruction (like fetching/storing an address)
      - Frequency of cycles is the clock speed (Hertz) - our current CPU has a 4.2 GHz base (so 4.2 billion cycles per second)
    - Done by Control Unit (CU) or ALU
  - Instruction Cycle
    - Cycle it takes CPU to process an entire instruction; made up of 4 phases
      - Fetch - Get address from Instruction Address Register (IAR), like the `rip` register
      - Decode - Take instruction from IAR and decode to binary to see what to execute
      - Execute - Fetch instruction operands from memory and process using ALU/CU
      - Store - Place the resulting value in the destination operand
  - Processes instructions using Instruction Set Architecture
    - This is either ComplexISC (Intel/AMD) or ReducedISC (ARM/Apple)
      - CISC enables more instructions (~1500) to be executed at once
        - Better for old programs since instructions were often combined into one
      - RISC splits instructions into minor ones, with the CPU optimized for a set of small instructions (~200)
- Registers
  - Fastest component of any computer, built within CPU core (thus very limited in size and number)
  - Two types:  
    - Data registers (`rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`, `r9`, `10`)
      - Used for storing instructions or syscall arguments
      - Primary data registers are `rax` through `rdx`
      - `rdi` and `rsi` are used for destination and source operands
      - Second data registers `r8-10` can be used when others are in use 
    - Pointer registers (`rbp`, `rsp`, `rip`)
      - Used to store specific important address pointers
      - `rbp` is the base stack pointer, keeping track of the beginning of the stack
      - `rsp` points to the current location within the stack (the top)
      - `rip` is the instruction pointer, showing the location of the next instructions
  - Sub-registers
    - Each register can be divided into sub-registers, which each divide by 2
      - For example: `rax` is 64 bits, `eax` is the lower 32 bits, `ax` is the lower 16 bites, and `al` is the lowest 8 bits
    - Sub-registers can be access/written-to on their own, so we don't need to use the full register with smaller amounts of data
  - Syscalls
    - On x86 systems, syscalls use the following format
      - `rax` is used for the syscall number - for example, `1` in `rax` means to print the data
      - `rdi`, `rsi`, `rdx`, `r10`, `r8`, and `r9` are used (in order given) as arguments for the syscall
- Memory addresses
  - `0x0` to `0xffffffffffffffff` (on 64 bit systems)
  - Split among the various sections of RAM (like stack and heap)
  - Multiple types of address fetching in x86
    - Immediate - value is given directly (like `add 2`)
    - Register - value in register (like `add rax`)
    - Direct - full address is given (like `call 0xffffffffaa8a25ff`)
    - Indirect - reference pointer is given (like `call [rax]`)
    - Stack - address is on top of the stack (like `add rsp`)
  - Endian-ness
    - Little-endian - little-end byte of address is filled/retrieved right to left
      - Address `0x0011223344556677` would be stored as `0x7766554433221100`
      - Used in Intel/AMD x86 operating systems, so shellcode will need to be right-to-left
    - Big-endian - store bytes as left-to-right

**Assembly File Structure**
- Contains labels, instructions, and operands (which are all sections)
  - Sections are are `.data`, which contain the variables, and `.text`, which contains the code to be executed
- Also contains directives (like `global _start`), which tells code to begin execution at `_start`
- Can define variables in the `.data` section using `db` for a list of bytes, `dw` for a list of words, `dd` for a list of digits
  - For example, `message db "Hello World!", 0x0a`
  - Can also use the `equ` instruction to evaluate an expression
    - Using this to define a label creates a constant that cannot be changed
    - `length equ $-message` would set `length` to equal the distance from where we're currently at to the value (which in this case is negative message), so `length` would be the length of `Hello World!`
- The `.text` holds all the assembly instructions and loads them into the `Text` portion of the stack (upon which they are executed)
  - This portion of the stack is read-only, which is why we define variables in the `Data` segment
- Code template:

```
global _start

section .data
    message db "Hello World!"
    length equ $-message

section .text
_start:
    mov rax, 1 ; syscall number 1 means use the sys_write syscall
    mov rdi, 1 ; 1st argument - file descriptor 1 means output to stdout
    mov rsi, message ; 2nd argument - pointer to message string
    mov rdx, length ; 3rd argument - number of bytes to write
    syscall

    mov rax, 60 ; syscall 60 is exit
    mov rdi, 0 ; 1st argument - return exit code 0
    syscall
```

**Assembling a file**
- Assembly is stored in `.s` or `.asm` files
  - For example, the above code template would work fine as an `.s` file
- We then assemble the file using `nasm`
  - `nasm -f elf64 {filename}.s`
  - This will output an assembled machine code `.o` file
- We then link the file using `ld`
  - `ld -o {output_name} {assembled_file}.o`
    - If the binary is 32-bit, add the `-m elf_i386` flag
  - This will give us our binary, which we can then make executable 

**Disassembling a file**
- We use `objdump` to dump the machine code from a file and interpret assembly into instructions
  - `objdump -M {syntax_like_intel} -d {binary} -s`
    - `-M` can be used to specify more disassembly instructions
    - `-s` is used for strings, so we can get stuff from the `text` section

**GDB**
- GNU Debugger works as a great debugging tool for binaries given good integration with linux and system components
- [GEF](https://github.com/hugsy/gef) - GDB Enhanced Features
  - Plugin for GDB; very useful for reverse engineering
  - Installed with `wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py` and then `echo source ~/.gdbinit-gef.py >> ~/.gdbinit`
    - Now, simply running `gdb {binary}` will open it up with GEF ready to go
- Has many different useful commands
- System information
  - `help {command}` - display usage of individual gdb commands (like the ones below)
  - `info {category}` - view general program information, such as functions, variables, breakpoints, or the stack
  - `disas {function_name}` - disassemble a function
  - `registers` - examine register contents
- Setting breakpoints and stepping through execution
  - `b {function_name}` - set an execution breakpoint on a function
    - `b *0x{memory_address}` - set a breakpoint at a specific point in memory
  - `d {breakpoint_id}` - delete a breakpoint 
  - `n` - go to the next function
  - `ni` - go to the next instruction (skipping function calls)
    - Can also use `si` for a more detailed instruction step-through (every single machine instruction run on the processor)
      - This will include things like calling `sum()`, whereas `ni` would skip over this
  - `c` - continue to next breakpoint
- Reading memory
  - `x/{count}{format}{size} {$register_or_0xAddress}` - examine memory at a certain point
    - `{count}` is the number of times to iterate
    - `{format}` is `x` for hex, `s` for string, and `i` for instruction
    - `{size}` is `b` for byte, `h` for halfword, `w` for word, `g` for giant (8 bytes)
    - Thus, `x/4xb $rip` would examine the next 4 instructions in 8 byte portions starting at the memory address stored in `rip`
- Modifying memory
  - Use `patch` (via GEF) to modify memory at a given address
    - `patch {type/size} {location} {values_to_change_to}`
      - The type can be `byte`, `word`, `dword`, `qword`, or `string`
  - If we don't have GEF, we can use `set` in GDB
    - For example, set registers with `set ${reg}={value}`
- Misc
  - `!command` - run a shell command (useful for something like `!strings`)