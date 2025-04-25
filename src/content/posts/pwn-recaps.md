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
