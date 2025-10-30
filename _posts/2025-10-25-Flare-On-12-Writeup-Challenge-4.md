---
title: Flare-On 12 Challenge 4 Writeup - UnholyDragon
date: 2025-10-25 04:00:00 +0300
tags:
  - CTF
  - flareon12
---

> Bag of Tricks: Python, 010 Editor
{: .prompt-tip }

# Challenge 4

## Finding the Binary Differences

When opening the challenge zip I'm met with a file with a weird name, `UnholyDragon-150.exe`.
The first thing I try to do is running it and I get the following message:

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030131345959.png)

Opening in `010 Editor` It's clear the `MZ` header is patched.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030131411953.png)

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030131423969.png)

After saving the changes to the file I see a new logo, nice.
Now I'll try running `UnholyDragon-150.exe`


![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030131434245.png)

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030132846859.png)

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030131509049.png)

It seemed to write 4 new files in order, and running each one in sequence.
Let's compare the files in the hex editor.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030131834952.png)

Looks like `150` and `151` only differ in a single byte, maybe every file has this byte offset in some distinct value and we need to brute force it.


![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030132150468.png)

Huh, different offset but still one byte difference, I'll check another two:

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030132238795.png)

Every two files in sequence differ in one byte at different offsets.
Meaning file `UnholyDragon-n.exe` and `UnholyDragon-n+5.exe` will differ in 5 bytes in distinct file locations.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030135127450.png)

After confirming this my theory is correct.
Even when deleting files `152` to `154` and running `151` it generates all files next after it until hitting `154`.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030132846859.png)

When running `154` nothing happens..

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030132934727.png)

When comparing `154`, the final file and the one that comes before it, `153` we see, as expected only a 1 byte difference at offset `0x6e8f8`.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030132614761.png)
## Scripting Away

I'll brute force this byte to make the program generate the next file correctly (`155`) but maybe a good value will give the flag, and maybe one of them will be interesting.

starting from 0xff down all the way until 0 (chose 0xff because `153` has in the diff with `154` the value 0xff).


```python
from os import system

DIFF_OFFSET_154 = 0x6e8f8

def main():
	data = open('UnholyDragon-154.exe', 'rb').read()
	
	for x in range(0xff, -1, -1):
	    do_write_file(f'test{x}.exe', x)
	    data[DIFF_OFFSET_154] = val
	    
		current_file = open(f'test{x}.exe', 'wb')
		current_file.write(data)
		current_file.close()
	
	    print(f'Running test{x}.exe')
	    res = os.system(f'test{x}.exe')
	    
if __name__ == '__main__':
	main()
```


![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030133110330.png)

When running the script I got a huge delay between first one and the other ones so i stopped the program.
when checking the processes I saw so many new processes from files I did not posses before, the files are also committed to the disk.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030133157388.png)

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030134221045.png)

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030133226495.png)

Also, looks like every executed file opens a blank WinForm.
To recap, `155` has it's byte with `154` as 0xff and when running it, 150 more files were generated and executed, each opening a form.
When going through the files, I checked out the old `150` file and saw it was actually replaced by a new one, that did not have the logo


![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030133345907.png)

## Back to the Roots (UnholyDragon-150.exe)

Opening the new `150` in 010 reveals we have a patched `MZ` header again.

![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030133411575.png)

I repatched the header proceeded to running the file:


![](/assets/2025-10-25-Flare-On-12-Writeup-Challenge-4/file-20251030133517009.png)