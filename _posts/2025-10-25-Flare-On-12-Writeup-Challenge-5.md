---
title: Flare-On 12 Challenge 5 Writeup - ntfsm
date: 2025-10-25 05:00:00 +0300
tags:
  - CTF
  - flareon12
---

> Bag of Tricks: IDA (finally!!!!), Powershell, Python
{: .prompt-tip }

# Challenge 5

## Basic Recon

This time around, we get an .exe file and nothing else.
The executable is almost 20MBs, so my first thought is that this is some kind of obfuscated binary, maybe bloated or contains resources.
As expected, opening the IDB the first time takes a while (I even stop the analysis with `idc.set_flag(INF_GENFLAGS, INFFL_AUTO, 0)`)

The file is huge, the first thing I do is looking at the imports/strings and checking if anything jumps to my eyes as interesting

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023083405474.png)
![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023083522186.png)
![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023083638347.png)
Okay, only from the imports I have a few assumptions

* The flag is hardcoded and decrypted using `BcryptDecrypt`, probably AES or something strong
* The command line is in use, probably the flag generating text is received from the user
* Some dynamic module loading is happening, with process creation
* There is some file work, probably relates to the challenge name: "**NTFS**m.exe"

Now, onto running the file:

```batch
>ntfsm.exe
usage: ./ntfsm <password>
to reset the binary in case of weird behavior: ./ntfsm -r
```

Why would a binary need a restart? Is it self-modifying in some way?
It seems assumption number 2 is correct, the user is prompted with a password and than some validation is probably done on/with it.


> "The command line is in use, probably the flag generating text is received from the user" - ✅

Okay, I'll try to input a password:

```batch
>ntfsm.exe skldmcdklscsd
input 16 characters
>ntfsm.exe AAAAAAAAAAAAAAAA
wrong!
```

Woah, when inputting the right length the program opens a billion cmds and `MessageBox` windows

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023083946768.png)

It appears there are 16 cmd.exe windows along with 16 message boxes, probably a new cmd and a new `MessageBoxW` for every password char(?)

> "Some dynamic module loading is happening, with process creation" - ✅

We have enough information, lets dive into the binary and look at the `bcrypt` module calls to identify a low-hanging fruit: Is the password used as an decryption key for the flag? What algorithm? Where is the flag stored?

### How is the Flag Generated? (Bcrypt Tracing)

The most important function in this context is `BCryptDecrypt` for obvious reasons, I'll see who calls it:

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023085358427.png)

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023085405046.png)

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023085414448.png)

Nice, 2 calls from the same procedure. This makes a lot of sense because usually you call `BCryptDecrypt` with `pbOutput = NULL` to get the actual plaintext buffer's size saved to the outparam to the `pcbResult` parameter.
![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023085626807.png)
![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023085700149.png)
Let's see if my assumption about the flag is correct

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023085842423.png)

Okay I'm not sure where `input` comes from, when trying to go to the callers of this function and it's wrapper we get a decompilation failure, probably obfuscation.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023085949151.png)

We'll dive deep into this big function later on in the research process, for now I have enough information to assume the flag is hardcoded and most likely decrypted with the SHA256 of the password.

#### Exhibit 1 - Hardcoded Ciphertext/IV

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023090229677.png)

#### Exhibit 2 - Win Print

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023090352157.png)

This is definitely enough for now:

> "The flag is hardcoded and decrypted using `BcryptDecrypt`, probably AES or something strong" - ✅

Now We'll move on to the `CreateFile`, `WriteFile`, `ReadFile` calls, I wanna know if my final assumption is correct, what does the **NTFS** has to do with the CTF, and how is it related to the win print/condition we just found.
## Discovering the ADS

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023091103424.png)

When tracing the xrefs to CreateFileA there are 2 exact copies of the same function, 2 `ReadFile` functions and 2 `WriteFile` functions, I'll break on the `ReadFile` ones first and check what is the value of `second_pointer`:

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023091457592.png)

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023091510870.png)

Wow! The NTFS comes to play in the form of ADS!

After continuing I see there is a total of 4 ADS:

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023093521791.png)
![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023093603520.png)
![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023093620725.png)

Remember the duplicates? It seems 1 `ReadFile` and 1 `WriteFile` handle `:input` and the other 2 handle the 3 other ADS: `:position, :transitions, :state`

After naming the functions, we get a pretty clear picture confirming my assumption from earlier:

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023090126824.png)

The big, non decompile-able function seem to handle the program logic and isn't obfuscated in any way, most of it's bloat is some switch-case (spoilers :D)

> "There is some file work, probably relates to the challenge name: "**NTFS**m.exe"" - ✅

### ADS' effect on the challenge run condition

It's pretty clear the `:input` ADS holds the program input.
After I've confirmed the 4 assumptions, I'll make new ones regarding the other 3 ADS:

* The `:position` ADS is related to `:input.at(index)`
* The `:state` ADS is the current ntfsm.exe process we are currently on (there are 16 subprocesses)

I have no idea what `:transitions` does, maybe it will come back to haunt me later.

#### Modifying/Reading the ADS using PS

Now, using powershell, I can read/write from ADS to modify them (might be handy later)

```powershell
[Byte[]] $data = 0x1,00,00,00,00,00,00,00
Set-Content -Path "ntfsm.exe" -Stream "state" -Value $data -Encoding Byte
Get-Content -Path "ntfsm.exe" -Stream "state" -Encoding Byte
```

> I have confirmed the program reads 8 bytes from the 3 non-input ADS and 16 chars from the input one.

#### Confirming assumptions using Python

I (chatgpt) wrote a simple script to log ADS changes to a file, I'll be using it to verify my assumptions

```python
import time
import sys
import os

LOG_FILE = "ads_log.txt"

def read_ads(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None
    except OSError as e:
        print(f"[!] Error reading {path}: {e}")
        return None

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <file> <ads_name>")
        sys.exit(1)

    file_path = sys.argv[1]
    ads_name = sys.argv[2]
    ads_path = f"{file_path}:{ads_name}"

    print(f"[*] Monitoring ADS: {ads_path}")
    seen = set()

    with open(LOG_FILE, "ab") as log:
        while True:
            data = read_ads(ads_path)
            if data is not None and data not in seen:
                seen.add(data)
                log.write(data + b"\n")
                log.flush()
                print(f"[+] New unique value: {data.hex()}")
            time.sleep(0.05)

if __name__ == "__main__":
    main()
```

```batch
>python script.py ntfsm.exe position
[*] Monitoring ADS: ntfsm.exe:position
[+] New unique value: 0000000000000000
```

```batch
> .\ntfsm.exe ABCDABCDABCDABCD
wrong!
```

And then...

```batch
[+] New unique value: 0100000000000000
[+] New unique value: 0200000000000000
[+] New unique value: 0300000000000000
[+] New unique value: 0400000000000000
[+] New unique value: 0500000000000000
[+] New unique value: 0600000000000000
[+] New unique value: 0700000000000000
[+] New unique value: 0800000000000000
[+] New unique value: 0900000000000000
[!] Error reading ntfsm.exe:position: [Errno 13] Permission denied: 'ntfsm.exe:position'
[+] New unique value: 0a00000000000000
[+] New unique value: 0b00000000000000
[+] New unique value: 0c00000000000000
[+] New unique value: 0d00000000000000
[+] New unique value: 0e00000000000000
[+] New unique value: 0f00000000000000
[+] New unique value: 1000000000000000
```

Boom! The permission denied is probably a race-condition to open a handle.
I'll do the same with `:state`:

```batch
>python script.py ntfsm.exe state
[*] Monitoring ADS: ntfsm.exe:state
[+] New unique value: ffffffffffffffff
[+] New unique value: 0000000000000000
```

Huh... Maybe the state is increased only after `:input.at(position)` is validated? I'll have to find the password validation to confirm this one, but 1/2 is good enough for now.

> "The `:position` ADS is related to `:input.at(index)" - ✅

Now gotta find the win condition, how is the password validated? The large function probably has something to do with that

## Win Condition?

### How is the input validated?

I traced the `read_input` function that reads from the ADS and see it has 2 calls, both from the big function.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023100431396.png)

The first one is the one I highlighted earlier, the input is saved into a local variable that is not referenced after this point:

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023100507735.png)

and `var_70` the decryption struct as I call it is also not referenced later on in the function.
Jumping to the second `read_input` we see the huge switch-case i hinted at earlier.
![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023100558294.png)
#### The Switch-Case

The switch-case is ginormous, has `USHORT_MAX` cases and each case besides the first one `46369` seem to look the same (The first one might be the win-condition, but I didn't need to know that in the end):

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023102002856.png)

* 🟩 - Start of case
* 🟥 - Lose condition - when the `:input.at(position) != any of the chars`
* 🟧 - When a match is found, the next case number is present here.
* 🟨🟦 - Win conditions of current case, `:input.at(position) == 'e'|'x'`
* 🟪 - Increase of `:state` confirmed by breakpoint, thus confirming assumption number 2

> ? How did I find the first state to put a breakpoint you ask? Hardware breakpoint read on the `:state`

> "The `:state` ADS is the current ntfsm.exe process we are currently on (there are 16 subprocesses)" - ✅

Final important Note - after the increase of `:state` the function that calls `CreateProcess` is called

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023102511602.png)

Final, Final note - After the state increase and in a new process' context the next case's number is saved and jumped to, the orange number from the case screenshot.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023102559982.png)
#### Funny Lock Troll

Some cases look like this:
![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023103044365.png)

If the current letter doesn't match any of the options `ExitWindowsEx` is called

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023103002392.png)

To me it looks like motivation to solve this using static analysis and scripting and not by dynamic - by hand debugging.

## Scripting it out

> Should have used `capstone`, but it is what it is.
> {: .prompt-tip }

After understanding the switch-case and program flow fully, we can identify the instructions to map and parse each case, creating logic chains of inputs starting from case number zero and continuing until finding a chain ending with 16 length.

* There are some cases that check up to 4 chars (maybe even 5 I don't remember) so doing this by hand seems really frustrating, and the lock troll sucks

Let's start top-down, assuming we can identify and parse each case separately.

```python
from typing import List

ADDRESSTABLE_ADDRESS = 0xc67bb8

def get_all_password_options(start_case_number = 0, password_prefix='') -> List[str]:
    all_options = []
    for char, int_value in parse_case(ADDRESSTABLE_ADDRESS + start_case_number * 4):
        new_prefix = password_prefix + char
        if len(new_prefix) < 16:
            all_options.extend(get_all_password_options(int_value, new_prefix))
        else:
            all_options.append(new_prefix)
    return all_options

def main():
    options = get_all_password_options()
    for option in options:
        print(option)

if __name__ == "__main__":
    main()
```

I got the switch case's address file offset by searching the hex bytes in 010 Editor and just grabbing the offset from the file start, this is obviously possible in IDA, after subtracting the sections RVA's and padding between them (for alignment).

Now, when we have a working `parse_case` function we can recursively call `get_all_password_options` with the start case for the chain and the password prefix.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023104013848.png)

You can think of it like a tree, at every intersection we recursively call `get_all_password_options` with all the chars until this point, and if the password was 4 chars long, the only option is "bdgz"

### Parsing the case bytes

Now, we only need a function to extract the chars from the `cmp/jmp` section and the next case number from the `jz` of each.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023110119736.png)
![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-5/file-20251023110135907.png)

```python
from struct import unpack
from typing import Tuple, List

FILENAME = "ntfsm.exe"
FILE_DATA = open(FILENAME, "rb").read()
MAX_CASE_SIZE = 0x100

CASE0_FILE_OFFSET = 0x85f641
CASE0_ADDRESS = 0x860241
CASE_PROLOG_SIZE = 0x22
DIFF_OFFSET = CASE0_ADDRESS - CASE0_FILE_OFFSET

def parse_case(case_address_raw: int) -> List[Tuple[chr, int]]:
    results = []
    case_address = unpack('<I', FILE_DATA[case_address_raw:case_address_raw+4])[0]
    case_file_offset = case_address - DIFF_OFFSET
    case_data = FILE_DATA[case_file_offset:case_file_offset + MAX_CASE_SIZE]
    case_end = case_data[CASE_PROLOG_SIZE:].find(b"\x0f\x31\x48\xc1\xe2\x20\x48\x0b\xc2")
    if case_end != -1:
        case_data = case_data[:case_end+CASE_PROLOG_SIZE]
    
    search_offset = 0
    PATTERN_SIZE = 10
    CHAR_OFFSET = 7
    JMP_OFFSET = 9
    NEXT_CASE_OFFSET = 8

    while True:
        pattern_offset = case_data.find(b"\x80\xBC\x24", search_offset)
        if pattern_offset == -1:
            break
        if pattern_offset + PATTERN_SIZE >= len(case_data):
            break
        char = chr(case_data[pattern_offset + CHAR_OFFSET])
        int_offset = case_data[pattern_offset + JMP_OFFSET]
        int_value = int.from_bytes(case_data[pattern_offset + PATTERN_SIZE + int_offset + NEXT_CASE_OFFSET:pattern_offset + PATTERN_SIZE + int_offset + NEXT_CASE_OFFSET + 4], "little")
        results.append((char, int_value))
        search_offset = pattern_offset + PATTERN_SIZE

    return results
```
## Amazing win

```batch
> python solve.py
iqg0nSeCHnOMPm2Q
```

```batch
>ntfsm.exe iqg0nSeCHnOMPm2Q
correct!
Your reward: f1n1t3_st4t3_m4ch1n3s_4r3_fun@flare-on.com
```

Very nice challenge, the first actual reversing one with a nice twist.