---
title: Flare-On 12 Challenge 2 Writeup - project_chimera
date: 2025-10-25 02:00:00 +0300
tags:
  - CTF
  - flareon12
---

> Bag of Tricks: Python
{: .prompt-tip }

# Challenge 2

The second challenge gave us a small python snippet
```python

# ================================================================= #
# ==           PROJECT CHIMERA - Dr. Alistair Khem's Journal     == #
# ==                  -- EYES ONLY --                            == #
# ================================================================= #
#
# Journal Entry 734:
#
# Success is within my grasp! After years of research, I have finally
# synthesized the two key components. The first, my 'Genetic Sequencer,'
# is stable and ready. It's designed to read and execute the final,
# most crucial part of my experiment: the 'Catalyst Serum.'
#
# The Catalyst is the key to creating a true digital lifeform.
# However, it is keyed to my specific biometric signature to prevent
# my research from falling into the wrong hands. Only I, the Lead
# Researcher, can successfully run this final protocol.
#
# If anyone else finds this, I urge you: DO NOT RUN THIS SCRIPT.
# The results could be... unpredictable.
#
# - Dr. A. Khem
#
import zlib
import marshal

# These are my encrypted instructions for the Sequencer.
encrypted_sequencer_data = ...bytes...

print(f"Booting up {f"Project Chimera"} from Dr. Khem's journal...")
# Activate the Genetic Sequencer. From here, the process is automated.
sequencer_code = zlib.decompress(encrypted_sequencer_data)
exec(marshal.loads(sequencer_code))

```
from the imports, message and actual code it is clear ```encrypted_suquencer_data``` is a `bytearray` of compressed python bytecode.
The program tries to execute the python code object after loading it to memory context using ```marshal.loads```. The first thing I'll do is observe the code object struct, what is in it and what can I  do with it (Only after running the bytecode myself :D).

## Layer 1

Let's start by looking at the code object's locals, names and imports, so we'll know what to do from here because it seems I used all clues from the original code.

```python
>>> print(top_code_obj.co_names)
('base64', 'zlib', 'marshal', 'types', 'encoded_catalyst_strand', 'print', 'b85decode', 'compressed_catalyst', 'decompress', 'marshalled_genetic_code', 'loads', 'catalyst_code_object', 'FunctionType', 'globals', 'catalyst_injection_function')
```
Wow, so much information. Looks like there is at least another layer from the `base64, zlib, marshal, b85decode, loads`.  Also, a lot of names seem to go with the story of the challenge and I really believe this is a self-unpacking multi-stage challenge, lets look at the `co_consts`
and see if there are any clues
```python
>>> for i, c in enumerate(top_code_obj.co_consts):
        print(i, type(c), repr(c)[:120])

Top-level constants (co_consts):
0 <class 'int'> 0
1 <class 'NoneType'> None
2 <class 'bytes'> b'c$|e+O>7&-6`m!Rzak~llE|2<;!(^*VQn#qEH||xE2b$*W=zw8NW~2mgIMj3sFjzy%<NJQ84^$vqeTG&mC+yhlE677j-8)F4nD>~?<GqL64olvBs$bZ4{q
3 <class 'str'> '--- Calibrating Genetic Sequencer ---'
4 <class 'str'> 'Decoding catalyst DNA strand...'
5 <class 'str'> 'Synthesizing Catalyst Serum...'
```
Okay, this is probably the second layer, lets use`marshal.loads(zlib.decompress(b85decode(layer2_bytes)))`.
Nice, we got a code object!

## Layer 2

Observing the `co_names` and `co_consts`:
```python
>>> print(inner_code_obj.co_names)
('os', 'sys', 'emoji', 'random', 'asyncio', 'cowsay', 'pyjokes', 'art', 'arc4', 'ARC4', 'activate_catalyst', 'run')
>>> for i, c in enumerate(inner_code_obj.co_consts):
            print(i, type(c), repr(c)[:120])
0 <class 'int'> 0
1 <class 'NoneType'> None
2 <class 'tuple'> ('ARC4',)
3 <class 'code'> <code object activate_catalyst at 0x0000017D3B919DF0, file "<catalyst_core>", line 15>
```
This is a troll :D, but between the trolls I see the ARC4 library, probably used for rc4 decryption/encryption of some sort, and also an inner code object, not compressed or anything.

> Keep in mind the RC4!

## Layer 3

As usual:

```python
>>> print(layer3.co_names)
('print', 'os', 'getlogin', 'encode', 'bytes', 'enumerate', 'asyncio', 'sleep', 'art', 'tprint', 'ARC4', 'decrypt', 'decode', 'cowsay', 'cow', 'pyjokes', 'get_joke', 'char_names', 'get_output_string', 'random', 'choice', 'sys', 'exit')
>>> ...
0 <class 'NoneType'> None
1 <class 'bytes'> b'm\x1b@I\x1dAoe@\x07ZF[BL\rN\n\x0cS'
2 <class 'bytes'> b'r2b-\r\x9e\xf2\x1fp\x185\x82\xcf\xfc\x90\x14\xf1O\xad#]\xf3\xe2\xc0L\xd0\xc1e\x0c\xea\xec\xae\x11b\xa7\x8c\xaa!\xa1\x9d\xc2\x90'
3 <class 'str'> '--- Catalyst Serum Injected ---'
4 <class 'str'> "Verifying Lead Researcher's credentials via biometric scan..."
5 <class 'code'> <code object <genexpr> at 0x0000026BBF8F5A30, file "<catalyst_core>", line 25>
6 <class 'float'> 0.01
7 <class 'str'> 'pending'
8 <class 'str'> 'AUTHENTICATION   SUCCESS'
9 <class 'str'> 'small'
10 <class 'tuple'> ('font',)
11 <class 'str'> 'Biometric scan MATCH. Identity confirmed as Lead Researcher.'
12 <class 'str'> 'Finalizing Project Chimera...'
13 <class 'str'> 'I am alive! The secret formula is:\n'
14 <class 'str'> 'AUTHENTICATION   FAILED'
15 <class 'str'> 'Impostor detected, my genius cannot be replicated!'
16 <class 'str'> 'The resulting specimen has developed an unexpected, and frankly useless, sense of humor.'
17 <class 'str'> 'en'
18 <class 'str'> 'all'
19 <class 'tuple'> ('language', 'category')
20 <class 'int'> 1
21 <class 'str'> 'System error: Unknown experimental state.'
```

Wow!! So much information! Filtering out the noise I see there is a code object (layer 4?) and 2 binary blobs, lets first look at the code object:

## Layer 4

```python
>>> ...
()
>>> ...
(42, None)
```
:O, very little information but there is a hardcoded 42. maybe `co_varnames` will help?

```python
>>> ...
('.0', 'i', 'c')
```
Okay this is a very simple function, maybe 
```python
for i, c in enumerate(iterable):
	...
```
Looks right, the 42 is probably the decompress key, I'll try to disassemble the function and look at the bytecode:

```python
>>> dis.dis(layer4)
 25           0 RETURN_GENERATOR
              2 POP_TOP
              4 RESUME                   0
              6 LOAD_FAST                0 (.0)
        >>    8 FOR_ITER                15 (to 42)
             12 UNPACK_SEQUENCE          2
             16 STORE_FAST               1 (i)
             18 STORE_FAST               2 (c)
             20 LOAD_FAST                2 (c)
             22 LOAD_FAST                1 (i)
             24 LOAD_CONST               0 (42)
             26 BINARY_OP                0 (+)
             30 BINARY_OP               12 (^)
             34 YIELD_VALUE              1
             36 RESUME                   1
             38 POP_TOP
             40 JUMP_BACKWARD           17 (to 8)
        >>   42 END_FOR
             44 RETURN_CONST             1 (None)
        >>   46 CALL_INTRINSIC_1         3 (INTRINSIC_STOPITERATION_ERROR)
             48 RERAISE                  1
ExceptionTable:
  4 to 44 -> 46 [0] lasti
```

Nice! lets recreate this in python

```python
def mystery(iterable):
    for i, c in iterable:
        yield c ^ (i + 42)
```

This is probably the RC4 key generator, let's try to give it the smaller binary blob from layer 3:

```python
>>> print(mystery(b'm\x1b@I\x1dAoe@\x07ZF[BL\rN\n\x0cS'))
G0ld3n_Tr4nsmut4t10n
```

Very good, now decrypting the bigger blob:

```python
>>> print(ARC4.new(key.encode()).decrypt(blob2).decode())
Th3_Alch3m1sts_S3cr3t_F0rmul4@flare-on.com
```

GG, onto number 3.