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


# BSidesSF 2025 
## acaan
- arb write to any file in the system
- two ways, plt overwrite or got overwrite
### plt
- write in /proc/self/mem, to the plt because open("/proc/self/mem") -> read() can write to `ro` mem
- write in the plt section shell code to pop a shell 

### got
- close@got -> main
- strncmp@got -> printf@got 
- strncmp@got(puts@got) (printf) -> libc
- overwrite strlen@got of libc with system 
- damn this one is cool
 


# UMass-2025
## fact 
- asks you to insert a name, send a small one, then chose the option `b` to do math, it will leak a pie address
- then chose `a` for renaming and jump to the `win` func
## riscy
- riscv64 chall, gives you a stack address and the goal is run shellcode, just find some shellcode online to open a shell and find the offset
- `gdb-multiarch`

# NexZero-2024
## calls
- small binary, there is no pop gadgets, the trick is to find the hidden `/bin/sh` string using strings cmd
- use read syscall as a `pop rax` gadget then do srop
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

# BSides-Algeria-2023
# just-pwn
- no free check, not write check and no read check
- tcache poisoning to arb read/write  to rce
- or fastbin poisoning with arb read/write to rce


