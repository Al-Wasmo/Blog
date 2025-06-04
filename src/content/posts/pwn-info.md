---
title: pwn info
published: 2025-04-25
description: 'collection of pwn links to varios intersting resources and info'
image: ''
tags: [pwn]
category: 'Writups'
draft: false 
lang: ''
---

# Info
- `__libc_csu_init` only works on version `2.34 <=` 

# Resources

## `heap`
- [house of fire <= 2.29](https://www.crow.rip/crows-nest/binexp/heap/house-of-force-i)
- [malloc_consolidate()
](https://ir0nstone.gitbook.io/notes/binexp/heap/malloc_consolidate)
    - cause a malloc_consolidate of fastbin chunks to get a unsortedbin chunk (libc leak)

## `risc` 
### rop
- [ROPing on RISC-V - hack-a-sat23](https://chalkiadakis.me/posts/hack-a-sat-23/riscv-pwn/)


## `kernel`
- [yuawn slides](https://speakerdeck.com/yuawn/kernel-exploitation?slide=20)
