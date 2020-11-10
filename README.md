# CS576ROP

We intend on creating a tool that extracts gadgets from provided ELF binaries and creates a loader that loads a secondary shellcode with executable permissions.

### Supported Platforms
Linux 64-bit

### Functionality: execute the shellcode.

### Input: one (or more) 64-bit ELF binaries.

### Output: the raw ROP payload to be executed.

We also intend on developing a tool for testing the output of our program. We will provide a bare-bones second-stage shellcode for the purpose of testing.

### Payload tester: an additional simple tool that will create a dummy process, load the executable(s) that contain the gadgets, load the ROP payload and a fixed second-stage shellcode, and execute it.

## Stretch Goals

We would like our ROP payload to be able to load code into/from the heap, and not only the stack.

Simple specification options for additional behaviors of the ROP payload.

## Deliverables

Source code and binary for the main ROP creation tool.

Source code and binary for payload tester and testing second-stage shellcode.

Video demonstration of the tool in action on a successful exploit.


### Honor Code
We pledge by the Stevens Honor Code.


- Specifications of your tool (what will the functionality be, inputs/outputs, supported platforms, etc.) Generally, everything the user of your tool needs to know.

- Design of your tool. What are the components of your tool, how do they connect, what kind of techniques are you using, what are the limitations (if any). Generally, everything a new developer that wants to modify the tool or someone that wants to recreate the tool needs to know.
