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
        - This will be `argc` at the start of execution 
      - `rip` is the instruction pointer, showing the location of the next instructions
  - Sub-registers
    - Each register can be divided into sub-registers, which each divide by 2
      - For example: `rax` is 64 bits, `eax` is the lower 32 bits, `ax` is the lower 16 bites, and `al` is the lowest 8 bits
    - Sub-registers can be access/written-to on their own, so we don't need to use the full register with smaller amounts of data
  - **Syscalls**
    - On x86 systems, syscalls use the following format
      - `rax` is used for the syscall number - for example, `1` in `rax` means to print the data
        - This will also store the result of the call
      - `rdi`, `rsi`, `rdx`, `rcx`, `r8`, and `r9` are used (in order given) as arguments for the syscall
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
    - `0x0a` is just a line feed (newline), placing it there just appends it to the string
    - Strings can also use format specifiers, like `%d`, to specify what type of string it is
  - Can also use the `equ` instruction to evaluate an expression
    - Using this to define a label creates a constant that cannot be changed
    - `length equ $-message` would set `length` to equal the distance from where we're currently at to the value (which in this case is negative message), so `length` would be the length of `Hello World!`
- The `.text` holds all the assembly instructions and loads them into the `Text` portion of the stack (upon which they are executed)
  - This portion of the stack is read-only, which is why we define variables in the `Data` segment
- Code template:

```S
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
  - `r` - run the program
    - `set args {args}` - can be used to set the arguments before execution
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

## Coding in Assembly

**Data Movement**
- `mov` to move a value into a register
  - `mov rax, 1` - puts 1 in `rax`
  - `mov rax, rsp` - moves the address in rsp into `rax`
  - `mov rax, [rsp]` - moves the value at rsp into `rax`
- `lea` to load an address with pointer arithmetic into a register
  - `lea rax, [rsp + 10]` - load the address of `rsp` + `0xa` into `rax` 
  - `lea rax, [rbx + rcx*4 + 32]` would load `rbx` + `rcx * 4` + `0x20` into `rax`

**Arithmetic**
- `inc` and `dec` to increment/decrement by 1
- `add`, `sub`, and `imul` to add/subtract/multiply destination by source

**Bitwise Instructions**
- `and`, `or`, `not`, and `xor` will all perform their respective operations
  - `or rax, rax` will just set `rax` to itself (same with `and`), whereas `xor` would set it to 0
  - `not rax` would invert `rax`

**Loops**
- Number of iterations for a loop should be set in the `rcx` register
  - `rcx` will be used, so if we forget to set our loop iterations here it could underflow from 0 lol
- Define a loop like a function, with `{loop_name}:` and instructions following
  - It should end in `loop {loop_name}`
- We technically don't need to initially jump to our loop, as execution will fall through after the end of our `_start` function

**Branching**
- We can jump to a function unconditionally with `jmp`
  - Since `jmp` doesn't decrement `rcx`, running `jmp` on the current function is basically a while true loop
- We can jump conditionally using other jump functions, depending on the flags set
  - `jz`/`jnz` - jump if destination equal to zero/not equal to zero
  - `js`/`jns` - jump if destination negative/non-negative
  - `jg`/`jge` - jump if destination greater than (or equal to) source
  - `jl`/`jle` - jump if destination lesser than (or equal to) source
- We can also use conditional functions, like `cmovz`, which moves the source into the destination if the zero flag is set
  - Same idea applies to something like `cmovl` or `setz`
- These conditions are met within the RFLAGS register
  - In order, the bits represent `Carry`, {Reserved}, `Parity`, {Reserved}, `Auxiliary Carry`, {Reserved}, `Zero`, `Sign`, `Trap`, `Interrupt`, `Direction`, `Overflow`
  - Aside from normal operations, we can set these flags with `cmp`, which will subtract the 2nd operand from the 1st and populate the flags accordingly
    - This can be handy if we don't want to actually modify any registers

**Using the Stack**
- We can push/pop from the stack as a form of temporary data storage
  - For example, perhaps before calling a function, we can `push rax` and then `pop` it afterward
- However, we have to push/pop registers totaling a multiple of 16 in size, otherwise it won't be 16-byte aligned
  - We can manually `sub` from `rsp` before calling a function if we aren't aligned, as long as we `add` to `rsp` afterward
    - However, if we're already pushing an even number of registers all of the same size (for example, `rax` and `rbx`), then we don't need to worry about stack alignment
- `rsp` points to the top, while `rbp` points to the base

**Subroutines**
- We can use subroutines to define functions, essentially
- We can use `call` to call a function, which basically pushes the instruction pointer to the stack (so we know where to return to) and then jumps to the associated point in memory
  - Then, within the function, we can `ret` to pop the address at `rsp` into `rip` and jump to it

**Functions**
- More complex than subroutines, as they must: 
  - Save registers to the stack
  - Pass function arguments
  - Fix stack alignment
  - Get function's return value and place in `rax`
- We can import functions with `extern {function}`, such as `printf` or `scanf`
  - Thus, in this case, we'd need to perform dynamic linking for the `libc` library within the `ld` function
    - Performed with `-lc --dynamic-linker /lib64/ld-linux-x86-64.so.2`
  - We can then move the format into `rdi` and the string to print into `rsi`, and then `call printf`
- When reading input with `scanf`, we'll need a buffer to hold the input
  - We can define this in the `.bss` section (after `.data`) with `{variable_name} resb {number_of_reserved_bytes}`


## Shellcode

- Shellcode is a hex representation of a binary's executable machine code

**Pwntools**
- Framework for sending shellcode to remote services
- Can assemble any code into shellcode
  - `pwn asm '{assembly}' -c '{arch_like_amd64}'`
- Can also extract shellcode from a binary
  - `python3 -c 'from pwn import *; file = ELF("{binary}"); print(file.section(".text").hex())'`
  - However, this shellcode likely won't be fixed, so we won't be able to immediately run it
- Can also run shellcode with `run_shellcode`:

```Python
from pwn import *; context(os="linux",arch="amd64",log_level="error")
run_shellcode(unhex("{shellcode}")).interactive()
```

**Shellcoding Techniques**
- To be proper shellcode, it must
  - Not contain variables
  - Not refer to direct memory addresses
  - Not contain any null bytes
- To not contain variables, we can repeatedly push data onto the stack
  - For example, if we wanted to push "Hello World!", we'd do `mov rbx, 'rld!'`, `push rbx`, `mov rbx, 'Hello Wo`, `push rbx`
  - Then, we can set `rsi` to `rsp` (`rsi` is the argument to print, and `rsp` is the current start of the string)
- To remove addresses, we need to only reference labels or relative addresses
  - This normally shouldn't be an issue, and if necessary we can push to the stack and use `rsp`
- To not have null bytes, we need to use registers matching the data size
  - For example, instead of `mov rax, 1`, we'd want to do `mov al, 1`

**Shellcoding Tools**
- We can disassemble assembly with `pwn disasm`
  - `pwn disasm '{shellcode}' -c 'amd64'`
- Crafting a `/bin/sh` using `execve` (syscall number 59)
- Our final function would be `execve("/bin//sh", ["/bin//sh"], NULL)`
  - We'll let `rax` hold `59` (syscall), `rdi` and `rsi` hold `['/bin//sh']` (pointer to program to execute and list of argument pointers), and `rdx` hold `NULL` (no env variables)
    - Added a second `/` to `/bin/sh` so it's 8 bytes
  - The assembly we'll end up running based on these constraints:

```S
global _start

section .text
_start:
  mov al, 59          ; execve syscall number
  xor rdx, rdx        ; set env to NULL
  push rdx            ; push NULL string terminator
  mov rdi, '/bin//sh' ; first arg to /bin/sh
  push rdi            ; push to stack 
  mov rdi, rsp        ; move pointer to ['/bin//sh']
  push rdx            ; push NULL string terminator
  push rdi            ; push second arg to ['/bin//sh']
  mov rsi, rsp        ; pointer to args
  syscall
```

- `pwn` also has `shellcraft`, which we can use to generate a `/bin/sh` shell with `pwn shellcraft amd64.linux.sh`
  - We can add on `-r` to run the shellcode
- We can also use `msfvenom` to generate or encode a payload
  - `msfvenom -p 'linux/x64/exec' CMD='sh' -a 'x64' --platform 'linux' -f 'hex'`
    - To obfuscate(?) a payload (to evade some antivirus), we can use `-e 'x64/xor'`
  - If we want to use msfvenom to encode a custom binary, we can write the bytes to a file and then pass to msfvenom
    - `objcopy -O binary -j .text {binary} {binary_name}.bin`
    - `msfvenom -p - -a 'x64' --platform 'linux' -f 'hex' < {binary_name}.bin` will give us the shellcode