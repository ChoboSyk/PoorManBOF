#!/bin/bash

# Compile the C code and extract the shellcode.
make shellcode -j 4

# Convert the shellcode to a C array.
xxd -i shellcode.bin > shellcode.h

#Remove adjuststack.o artefact
rm adjust-stack.o

echo "Shellcode can be found in shellcode.bin in raw format or shellcode.h in C array"
