---
title: Flare-On 12 Challenge 1 Writeup - Drill Baby Drill
date: 2025-10-25 01:00:00 +0300
tags:
  - CTF
  - flareon12
---

> Bag of Tricks: Python
{: .prompt-tip }

# Challenge 1

This challenge was very simple, we received a pygame Python game exe and the source code.
I didn't bother running the exe and just looked at the code:
```python
flagfont = pygame.font.Font("fonts/VT323-Regular.ttf", 32)
flag_text_surface = flagfont.render("nope@nope.nope", False, pygame.Color('black'))
flag_message_text_surface1 = flagfont.render("You win! Drill Baby is reunited with", False, pygame.Color('yellow'))
flag_message_text_surface2 = flagfont.render("all its bears. Welcome to Flare-On 12.", False, pygame.Color('yellow'))
```
These messages are a nice clue, the flag must be rendered sometime in the regular game loop.
Continued the CTRL+F and found this function, that looks like a flag decryptor:

```python
def GenerateFlagText(sum):
    key = sum >> 8
    encoded = "\xd0\xc7\xdf\xdb\xd4\xd0\xd4\xdc\xe3\xdb\xd1\xcd\x9f\xb5\xa7\xa7\xa0\xac\xa3\xb4\x88\xaf\xa6\xaa\xbe\xa8\xe3\xa0\xbe\xff\xb1\xbc\xb9"
    plaintext = []
    for i in range(0, len(encoded)):
        plaintext.append(chr(ord(encoded[i]) ^ (key+i)))
    return ''.join(plaintext)
```

Pretty reasonable, takes in a sum and xors it byte by byte with the flag ciphertext, lets see how this sum is generated:

```python
if player.hitBear():
    player.drill.retract()
    bear_sum *= player.x
    bear_mode = True

if bear_mode:
    screen.blit(bearimage, (player.rect.x, screen_height - tile_size))
    if current_level == len(LevelNames) - 1 and not victory_mode:
        victory_mode = True
        flag_text = GenerateFlagText(bear_sum)
        print("Your Flag: " + flag_text)
```

Nice, the sum is just multiplications of the player.x coords, the max X is 800, let's write a quick script to count to 800 (obviously the sum can be huge, but this is the first challenge)

```python
def GenerateFlagText(sum):
    key = sum
    encoded = "\xd0\xc7\xdf\xdb\xd4\xd0\xd4\xdc\xe3\xdb\xd1\xcd\x9f\xb5\xa7\xa7\xa0\xac\xa3\xb4\x88\xaf\xa6\xaa\xbe\xa8\xe3\xa0\xbe\xff\xb1\xbc\xb9"
    plaintext = []
    for i in range(0, len(encoded)):
        plaintext.append(chr(ord(encoded[i]) ^ (key+i)))
    return ''.join(plaintext)

def brute_force_flag():
    for i in range(800):
        flag = GenerateFlagText(i)

        if "flare" in flag:
            print(flag)
            return

def main():
    brute_force_flag()

if __name__ == '__main__':
    main()
```

![](assets/2025-10-25-Flare-On-12-Writeup-Challenge-1/file-20251018095228588.png)

:)