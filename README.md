# xdbg-ELF-Analysis-and-Debugging-Tool

`xdbg` is a Linux-focused ELF analysis and debugging tool written in C. It provides ELF inspection, x86-64 disassembly with explanations, local debugging, and remote debugging support.

## Features

### 1. ELF Inspector

Displays the ELF header, program header table, section header table, and symbol tables in a readable format, similar to `readelf`.

It also reports common security properties such as stack canaries, NX, PIE, RELRO, and risky function usage.

**Usage:**

```bash
./build/bin/xdbg-elf analyze <elf-binary>
```

### 2. x86-64 Instruction Decoder

Provides detailed disassembly of the `.text` section and gives full step-by-step instruction explanations.

**Usage:**

```bash
./build/bin/xdbg-elf decode <elf-binary> [instruction-count]
```

### 3. Debugger

A debugger that supports breakpoints, single-stepping, register inspection, and memory reading and writing.

**Usage:**

```bash
./build/bin/xdbg-elf debug [program] [args...]
```

### 4. Remote Debugger

Remote debugging support.

**Usage:** 

```bash
 ./build/bin/xdbg-elf remote-worker <host:port> [program] [args...]
 ./build/bin/xdbg-elf remote-client <host:port>
```

## Examples of Use

### 1. ELF Inspector
We analyze this program, `hello.asm`, which is a simple AT&T x86 assembly program that prints “Hello World” to the screen.

<img width="224" height="218" alt="image" src="https://github.com/user-attachments/assets/235b3817-73b4-45e0-92dc-05423cb2617e" />

Command:

<img width="864" height="19" alt="image" src="https://github.com/user-attachments/assets/a296f26b-e7d6-4306-823a-12edec17e85b" />

ELF header:

<img width="312" height="178" alt="image" src="https://github.com/user-attachments/assets/7adf146b-b38c-48b9-91bd-d7d24bcf6eae" />

Program headers:

<img width="911" height="85" alt="image" src="https://github.com/user-attachments/assets/461c7e1f-2435-4445-bd59-cb4cef086518" />

Section header table:

<img width="677" height="185" alt="image" src="https://github.com/user-attachments/assets/366a2872-ca76-474f-9c81-e246ffb0f1f1" />

Symbol table:

<img width="649" height="181" alt="image" src="https://github.com/user-attachments/assets/57b603e3-5680-436f-bac3-6ceaf7ab718c" />

Security report:

<img width="257" height="215" alt="image" src="https://github.com/user-attachments/assets/7d3c0dab-2414-4943-9f0f-f34985878732" />


### 2. x86-64 Instruction Decoder
We analyze the same program as before, hello.asm

<img width="224" height="218" alt="image" src="https://github.com/user-attachments/assets/235b3817-73b4-45e0-92dc-05423cb2617e" />

Command:

<img width="851" height="26" alt="image" src="https://github.com/user-attachments/assets/bb3f9999-619f-4b3e-8c68-45a62d6d65d1" />

disassembly:

<img width="561" height="172" alt="image" src="https://github.com/user-attachments/assets/6e191cf3-20f6-4f2b-9035-18cbade396b9" />

Explanation and breaking down each instruction:

<img width="650" height="446" alt="image" src="https://github.com/user-attachments/assets/b9da8cf0-5e65-4e0c-96b2-d482c881193b" />


### 3. Debugger
We debug the same program as before, hello.asm

<img width="224" height="218" alt="image" src="https://github.com/user-attachments/assets/235b3817-73b4-45e0-92dc-05423cb2617e" />

Debugger Video Demo:

https://github.com/user-attachments/assets/85d8b03c-d74d-47e9-9e37-0fbfd08e55a7




