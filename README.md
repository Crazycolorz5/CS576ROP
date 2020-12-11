# CS576ROP

We intend on creating a tool that extracts gadgets from provided ELF binaries and creates a loader that loads a secondary shellcode with executable permissions.

### Supported Platforms
Linux 64-bit

### Usage
The script main.py is to be run with python3.
For all support options, execute
`python3 main.py --help`

### Functionality: execute the shellcode.

Our tool will be able to do the following:
1) Extract useful gadgets from provided binaries (ELF files).
2) Automatically assemble gadgets to form a payload that gives the user a working sh shell.

## Dependencies / Installation

### Python3
We intend to create the tool in Python3.

### Capstone
We will use Capstone as our x86_64 disassembler, to aid in the locating of gadgets.
This can be installed with `pip install capstone`.
Alternatively, a requirements file is provided, so one may execute:
`pip install -r requirements.txt`.

## Input: one (or more) 64-bit ELF binaries.

## Outputs

### Useful gadgets

### A script to create the raw ROP payload to be executed.

## Design Notes

We will have a module for extracting as many gadgets as possible from a given binary.
We will have a set of functions that searches gadgets for various behaviors that are useful building block.
We will have a script that assembles a pre-defined execve shellcode from the former two.
There will be a separate vulnerable program and test shellcodes.

## Stretch Goals

We would like our ROP payload to be able to load code into/from the heap, and not only the stack.

Simple specification options for additional behaviors of the ROP payload.

## Deliverables

Source code and binary for the main ROP creation tool.

Source code and binary for example second-stage shellcode.
This is available in the print_passwd folder.
The code should just be compiled with `make` while in the directory.

Video demonstration of the tool in action on a successful exploit.


## Authors & Honor Code
In alphabetical order:
 - Chen, Adam
 - Rodman, Dean
 - Rose, Ben
 - Trivedi, Devharsh
 - Zhang, Yuchen

We pledge by the Stevens Honor Code.
