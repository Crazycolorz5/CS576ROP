# CS576ROP

We intend on creating a tool that extracts gadgets from provided ELF binaries and creates a loader that loads a secondary shellcode with executable permissions.

### Supported Platforms
Linux 64-bit

### Functionality: execute the shellcode.

Our tool will be able to do the following:
1) Extract useful gadgets from provided binaries (ELF files).
2) Automatically assemble gadgets to form a payload that transfers control over to a secondary shellcode.
    (Or -- launch sh/bash?)
3) Provide a testing environment for the generated shellcode.

### Dependencies

## Python3
We intend to create the tool in Python3.

## Capstone
We will use Capstone as our x86_64 disassembler, to aid in the locating of gadgets.
This can be installed with `pip install capstone`.

### Input: one (or more) 64-bit ELF binaries.

### Outputs
## Useful gadgets

## The raw ROP payload to be executed.

We also intend on developing a tool for testing the output of our program. We will provide a bare-bones second-stage shellcode for the purpose of testing.

### Payload tester: an additional simple tool that will create a dummy process, load the executable(s) that contain the gadgets, load the ROP payload and a fixed second-stage shellcode, and execute it.


### Design Notes

We will have a module for extracting gadgets and categorize them based on function (uses control flow analysis).
We will have a solver that assembles gadgets of various functions into arbitary behaviors.
We will have a script that assembles a pre-defined bootloading shellcode from the former two.
There will be a separate vulnerable program and code for the bootloading shellcode to be modifiable.

## Stretch Goals

We would like our ROP payload to be able to load code into/from the heap, and not only the stack.

Simple specification options for additional behaviors of the ROP payload.

## Deliverables

Source code and binary for the main ROP creation tool.

Source code and binary for payload tester and testing second-stage shellcode.

Video demonstration of the tool in action on a successful exploit.


### Authors & Honor Code
In alphabetical order:
 - Chen, Adam
 - Rodman, Dean
 - Rose, Ben
 - Trivedi, Devharsh
 - Zhang, Yuchen

We pledge by the Stevens Honor Code.
