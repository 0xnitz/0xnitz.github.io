---
title: Flare-On 12 Challenge 6 Writeup - Chain of Demands
date: 2025-10-25 06:00:00 +0300
tags:
  - CTF
  - flareon12
---

> Bag of Tricks: Python
{: .prompt-tip }

# Challenge 6

## Recon

The challenge is started with a single ELF file, before running it let's check is `file` can say something interesting about it

```bash
6_-_Chain_of_Demands$ file chat_client
chat_client: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=81544629ae0a32249a48b0bc5134fb7b1455adea, stripped
```

Hmm, nothing interesting, I'll run it

```bash
6_-_Chain_of_Demands$ ./chat_client
[SETUP]  - Generated Seed 79066037771727090551269662459584693643225652888432587028756501698761944874574...
[SETUP] Generating LCG parameters from system artifact...
[SETUP]  - Found parameter 1: 85930520411859274111...
[SETUP]  - Found parameter 2: 86347681057443062706...
[SETUP]  - Found parameter 3: 72631930525854253327...
[!] Connection error: [!] Failed to connect to Ethereum network at
Please check your RPC_URL and network connection.
[SETUP] LCG Oracle is on-chain...
[!] Connection error: [!] Failed to connect to Ethereum network at
Please check your RPC_URL and network connection.
[SETUP] Triple XOR Oracle is on-chain...
[SETUP] Crypto backend initialized...
[RSA] Generating RSA key from on-chain LCG primes...
[!] Connection error: [!] Failed to connect to Ethereum network at
Please check your RPC_URL and network connection.
```

![](assets/2025-10-25-Flare-On-12-Writeup-Challenge-6/file-20251023130226143.png)

This is definitely a crypto challenge, reversing will probably take a backseat for this one.
The main window has a few buttons, and a text box for sending chat messages.
when clicking on the `Enable Super-Safe Encryption` check and turning it on/off we get these logs:

![](assets/2025-10-25-Flare-On-12-Writeup-Challenge-6/file-20251023130250453.png)

Nice, there is a weak encryption (LCG-XOR) and a strong one (RSA) that we can switch between.

When connecting to the ip address we get this message:

![](assets/2025-10-25-Flare-On-12-Writeup-Challenge-6/file-20251023130302414.png)

And we can experiment with messaging, all generating a lot of logs via the bash window.

```bash
[+] Calling nextVal() with _currentState=79066037771727090551269662459584693643225652888432587028756501698761944874574
Exception in thread Thread-1 (generate_rsa_and_update_gui):
Traceback (most recent call last):
  File "threading.py", line 1075, in _bootstrap_inner
  File "threading.py", line 1012, in run
  File "challenge_to_compile.py", line 439, in generate_rsa_and_update_gui
  File "challenge_to_compile.py", line 227, in generate_rsa_key_from_lcg
  File "challenge_to_compile.py", line 120, in get_next
AttributeError: 'NoneType' object has no attribute 'functions'
[SETUP]  - Generated Seed 79066037771727090551269662459584693643225652888432587028756501698761944874574...
[SETUP] Generating LCG parameters from system artifact...
[SETUP]  - Found parameter 1: 85930520411859274111...
[SETUP]  - Found parameter 2: 86347681057443062706...
[SETUP]  - Found parameter 3: 72631930525854253327...
[!] Connection error: [!] Failed to connect to Ethereum network at
Please check your RPC_URL and network connection.
[SETUP] LCG Oracle is on-chain...
[!] Connection error: [!] Failed to connect to Ethereum network at
Please check your RPC_URL and network connection.
[SETUP] Triple XOR Oracle is on-chain...
[SETUP] Crypto backend initialized...
[CONFIG] Web3 RPC URL updated to: asdfasdfa
[CONFIG] Web3 Private Key updated.
[SETUP]  - Generated Seed 79066037771727090551269662459584693643225652888432587028756501698761944874574...
[SETUP] Generating LCG parameters from system artifact...
[SETUP]  - Found parameter 1: 85930520411859274111...
[SETUP]  - Found parameter 2: 86347681057443062706...
[SETUP]  - Found parameter 3: 72631930525854253327...
[!] Connection error: [!] Failed to connect to Ethereum network at asdfasdfa
Please check your RPC_URL and network connection.
[SETUP] LCG Oracle is on-chain...
[!] Connection error: [!] Failed to connect to Ethereum network at asdfasdfa
Please check your RPC_URL and network connection.
[SETUP] Triple XOR Oracle is on-chain...
[SETUP] Crypto backend initialized...

[+] Calling nextVal() with _currentState=79066037771727090551269662459584693643225652888432587028756501698761944874574
Exception in Tkinter callback
Traceback (most recent call last):
  File "tkinter/__init__.py", line 1971, in __call__
  File "challenge_to_compile.py", line 425, in send_message_event
  File "challenge_to_compile.py", line 281, in process_message
  File "challenge_to_compile.py", line 120, in get_next
AttributeError: 'NoneType' object has no attribute 'functions'
```

The last button, and probably the most interesting one is the `Last Convo` revealing a chat history window with plain/ciphertext!!!

![](assets/2025-10-25-Flare-On-12-Writeup-Challenge-6/file-20251023130325276.png)

This is huge, we have the RSA public key, and the weaker encryption's plain/ciphertexts, maybe the challenge won't require us to send/play with any of the live features ourselves and be purely crypto.

Extracting the JSON for later use:


```json
[
  {
    "conversation_time": 0,
    "mode": "LCG-XOR",
    "plaintext": "Hello",
    "ciphertext": "e934b27119f12318fe16e8cd1c1678fd3b0a752eca163a7261a7e2510184bbe9"
  },
  {
    "conversation_time": 4,
    "mode": "LCG-XOR",
    "plaintext": "How are you?",
    "ciphertext": "25bf2fd1198392f4935dcace7d747c1e0715865b21358418e67f94163513eae4"
  },
  {
    "conversation_time": 11,
    "mode": "LCG-XOR",
    "plaintext": "Terrible...",
    "ciphertext": "c9f20e5561acf172305cf8f04c13e643c988aa5ab29b5499c93df112687c8c7c"
  },
  {
    "conversation_time": 13,
    "mode": "LCG-XOR",
    "plaintext": "Is this a secure channel?",
    "ciphertext": "3ab9c9f38e4f767a13b12569cdbf13db6bbb939e4c8a57287fb0c9def0288e46"
  },
  {
    "conversation_time": 16,
    "mode": "LCG-XOR",
    "plaintext": "Yes, it's on the blockchain.",
    "ciphertext": "3f6de0c2063d3e8e875737046fef079d73cc9b1b7a4b7b94da2d2867493f6fc5"
  },
  {
    "conversation_time": 24,
    "mode": "LCG-XOR",
    "plaintext": "Erm enable super safe mode",
    "ciphertext": "787cf6c0be39caa21b7908fcd1beca68031b7d11130005ba361c5d361b106b6d"
  },
  {
    "conversation_time": 30,
    "mode": "LCG-XOR",
    "plaintext": "Ok, activating now",
    "ciphertext": "632ab61849140655e0ee6f90ab00b879a3a3da241d4b50bab99f74f169d456db"
  },
  {
    "conversation_time": 242,
    "mode": "RSA",
    "plaintext": "[ENCRYPTED]",
    "ciphertext": "680a65364a498aa87cf17c934ab308b2aee0014aee5b0b7d289b5108677c7ad1eb3bcfbcad7582f87cb3f242391bea7e70e8c01f3ad53ac69488713daea76bb3a524bd2a4bbbc2cfb487477e9d91783f103bd6729b15a4ae99cb93f0db22a467ce12f8d56acaef5d1652c54f495db7bc88aa423bc1c2b60a6ecaede2f4273f6dce265f6c664ec583d7bd75d2fb849d77fa11d05de891b5a706eb103b7dbdb4e5a4a2e72445b61b83fd931cae34e5eaab931037db72ba14e41a70de94472e949ca3cf2135c2ccef0e9b6fa7dd3aaf29a946d165f6ca452466168c32c43c91f159928efb3624e56430b14a0728c52f2668ab26f837120d7af36baf48192ceb3002"
  },
  {
    "conversation_time": 249,
    "mode": "RSA",
    "plaintext": "[ENCRYPTED]",
    "ciphertext": "6f70034472ce115fc82a08560bd22f0e7f373e6ef27bca6e4c8f67fedf4031be23bf50311b4720fe74836b352b34c42db46341cac60298f2fa768f775a9c3da0c6705e0ce11d19b3cbdcf51309c22744e96a19576a8de0e1195f2dab21a3f1b0ef5086afcffa2e086e7738e5032cb5503df39e4bf4bdf620af7aa0f752dac942be50e7fec9a82b63f5c8faf07306e2a2e605bb93df09951c8ad46e5a2572e333484cae16be41929523c83c0d4ca317ef72ea9cde1d5630ebf6c244803d2dc1da0a1eefaafa82339bf0e6cf4bf41b1a2a90f7b2e25313a021eafa6234643acb9d5c9c22674d7bc793f1822743b48227a814a7a6604694296f33c2c59e743f4106"
  }
]
```

### Finding the Win Condition From The Logs

#### Program GUI Logs

There are 2 types of encryption, a weak XOR-LCG one and a strong RSA one.

> ❓The flag is probably received after getting the RSA private key

#### Bash Logs

The challenge is entirely Python, and seem to use proprietary implementation for most crypto features, and a Tkinter GUI.

> ❓The ELF is most likely pyinstaller

We receive the SEED of the encryption (or part of it) and a snippet of the 3 primes used for the LCG-XOR, that will probably be very useful for later.

> ❓Because we have `conversation_time` in the chat logs, we can most likely guess the SEED and find out the primes ourselves, thus breaking the weaker encryption. We have the plain/cipher pairs for a reason, breaking the weaker encryption will probably help in guessing RSA params thus making it weak.
#### Chat Messages

The chat messages are between two users, that seem to activate the check mark we saw in the GUI, so they switch from XOR-LCG to RSA super safe encryption

> ❓The flag is most likely one of the RSA messages decrypted.

Now we understand almost everything, all we are missing is the encryption proprietary implementation so we can hopefully find a weakness in it/writing the prime guessing logic ourselves. 

## Extracting the Source Code

### From ELF/pyinstaller to pyc Folder

The first step is getting from ELF to pyc, for that I used [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor):

```bash
/6_-_Chain_of_Demands/writeup$ python3 ../pyinstxtractor.py ../chat_client
[+] Processing ../chat_client
[+] Pyinstaller version: 2.1+
[+] Python version: 3.12
[+] Length of package: 31946910 bytes
[+] Found 553 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: pyi_rth_setuptools.pyc
[+] Possible entry point: pyi_rth_pkgres.pyc
[+] Possible entry point: pyi_rth__tkinter.pyc
[+] Possible entry point: challenge_to_compile.pyc
[+] Found 1090 files in PYZ archive
[+] Successfully extracted pyinstaller archive: ../chat_client

You can now use a python decompiler on the pyc files within the extracted directory
```

```bash
6_-_Chain_of_Demands$ ls chat_client_extracted/ | grep pyc
challenge_to_compile.pyc
challenge_to_compile_copy.pyc
pyi_rth__tkinter.pyc
pyi_rth_inspect.pyc
pyi_rth_multiprocessing.pyc
pyi_rth_pkgres.pyc
pyi_rth_pkgutil.pyc
pyi_rth_setuptools.pyc
pyiboot01_bootstrap.pyc
pyimod01_archive.pyc
pyimod02_importers.pyc
pyimod03_ctypes.pyc
struct.pyc
```

The file that jumps to my eyes is `challenge_to_compile.pyc`, this is probably the challenge source code.
### From pyc to .py

Because the challenge is written in new-ish Python, `uncompyle6` won't work here, so I used [PyLingual](https://pylingual.io/).

## Understanding the Source and Encryption Internals

From the imports we see that this is the chat app presented to us earlier, without anything fancy

```python
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, Checkbutton, BooleanVar, Toplevel
import platform
import hashlib
import time
import json
from threading import Thread
import math
import random
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime
import os
import sys
from web3 import Web3
from eth_account import Account
from eth_account.signers.local import LocalAccount
```

We do have some smart contract related libraries but lets hope the crypto stays simple and parallel to my previous assumptions.

### Crypto Backend

```python
class TripleXOROracle:
    def __init__(self):
        self.contract_bytes = '6103...'
        self.contract_abi = [{'inputs': [{'internalType': 'uint256', 'name': '_primeFromLcg', 'type': 'uint256'}, {'internalType': 'uint256', 'name': '_conversationTime', 'type': 'uint256'}, {'internalType': 'string', 'name': '_plaintext', 'type': 'string'}], 'name': 'encrypt', 'outputs': [{'internalType': 'bytes32', 'name': '', 'type': 'bytes32'}], 'stateMutability': 'pure', 'type': 'function'}]
        self.deployed_contract = None

    def deploy_triple_xor_contract(self):
        self.deployed_contract = SmartContracts.deploy_contract(self.contract_bytes, self.contract_abi)

    def encrypt(self, prime_from_lcg, conversation_time, plaintext_bytes):
        print(f'\n[+] Calling encrypt() with prime_from_lcg={prime_from_lcg}, time={conversation_time}, plaintext={plaintext_bytes}')
        ciphertext = self.deployed_contract.functions.encrypt(prime_from_lcg, conversation_time, plaintext_bytes).call()
        print(f'  _ciphertext = {ciphertext.hex()}')
        return ciphertext
```

This is a simple enough XOR cipher, the only non-trivial gist is the use of smart contracts, but because we have the hardcoded contract I still believe we can work around it

```python
class SmartContracts:
    rpc_url = ''
    private_key = ''

    def deploy_contract(contract_bytes, contract_abi):
        try:
            w3 = Web3(Web3.HTTPProvider(SmartContracts.rpc_url))
            if not w3.is_connected():
                raise ConnectionError(f'[!] Failed to connect to Ethereum network at {SmartContracts.rpc_url}')
            print(f'[+] Connected to Sepolia network at {SmartContracts.rpc_url}')
            print(f'[+] Current block number: {w3.eth.block_number}')
            if not SmartContracts.private_key:
                raise ValueError('Please add your private key.')
            account = Account.from_key(SmartContracts.private_key)
            w3.eth.default_account = account.address
            print(f'[+] Using account: {account.address}')
            balance_wei = w3.eth.get_balance(account.address)
            print(f"[+] Account balance: {w3.from_wei(balance_wei, 'ether')} ETH")
            if balance_wei == 0:
                print('[!] Warning: Account has 0 ETH. Deployment will likely fail. Get some testnet ETH from a faucet (e.g., sepoliafaucet.com)!')
            Contract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytes)
            gas_estimate = Contract.constructor().estimate_gas()
            print(f'[+] Estimated gas for deployment: {gas_estimate}')
            gas_price = w3.eth.gas_price
            print(f"[+] Current gas price: {w3.from_wei(gas_price, 'gwei')} Gwei")
            transaction = Contract.constructor().build_transaction({'from': account.address, 'nonce': w3.eth.get_transaction_count(account.address), 'gas': gas_estimate + 200000, 'gasPrice': gas_price})
            signed_txn = w3.eth.account.sign_transaction(transaction, private_key=SmartContracts.private_key)
            print('[+]  Deploying contract...')
            tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
            print(f'[+] Deployment transaction sent. Hash: {tx_hash.hex()}')
            print('[+] Waiting for transaction to be mined...')
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            print(f'[+] Transaction receipt: {tx_receipt}')
            if tx_receipt.status == 0:
                print('[!] Transaction failed (status 0). It was reverted.')
                return
            contract_address = tx_receipt.contractAddress
            print(f'[+] Contract deployed at address: {contract_address}')
            deployed_contract = w3.eth.contract(address=contract_address, abi=contract_abi)
            return deployed_contract
        except ConnectionError as e:
            print(f'[!] Connection error: {e}')
            print('Please check your RPC_URL and network connection.')
            return None
        except ValueError as e:
            print(f'[!] Configuration error: {e}')
            return None
        except Exception as e:
            print(f'[!] An unexpected error occurred: {e}')
            return None
```

As expected, the contract is initialized from a byte sequence using the `Web3` library.
Also, now we know the `conversation_time` does in fact play a part in the encryption.

As for the main classes, `ChatApp` houses the tkinter GUI and `ChatLogic` the cryptographic backend.
A question that I asked myself when reading this is, where are the primes coming from? How is the seed generated?
The answers to these questions come from the `ChatLogic` class, handling the backend.

```python
def _get_system_artifact_hash(self):
        artifact = platform.node().encode('utf-8')
        hash_val = hashlib.sha256(artifact).digest()
        seed_hash = int.from_bytes(hash_val, 'little')
        print(f'[SETUP]  - Generated Seed {seed_hash}...')
        return seed_hash
```

The seed is the `SHA256` of the computer name!

```python
    def _generate_primes_from_hash(self, seed_hash):
        primes = []
        current_hash_byte_length = (seed_hash.bit_length() + 7) // 8
        current_hash = seed_hash.to_bytes(current_hash_byte_length, 'little')
        print('[SETUP] Generating LCG parameters from system artifact...')
        iteration_limit = 10000
        iterations = 0
        while len(primes) < 3 and iterations < iteration_limit:
            current_hash = hashlib.sha256(current_hash).digest()
            candidate = int.from_bytes(current_hash, 'little')
            iterations += 1
            if candidate.bit_length() == 256 and isPrime(candidate):
                primes.append(candidate)
                print(f'[SETUP]  - Found parameter {len(primes)}: {str(candidate)[:20]}...')
        if len(primes) < 3:
            error_msg = '[!] Error: Could not find 3 primes within iteration limit.'
            print('Current Primes: ', primes)
            print(error_msg)
            exit()
        return (primes[0], primes[1], primes[2])
```

And the primes come from continuous hashing of the computer name until a prime-hash is found.

![](assets/2025-10-25-Flare-On-12-Writeup-Challenge-6/file-20251023152452116.png)
Meaning, XORing the ciphertext with the plaintext results us with the `prime ^ conversation_time` and because we have the conversation time, we can solve for the LCG primes!

### RSA

```python
def generate_rsa_key_from_lcg(self):
        print('[RSA] Generating RSA key from on-chain LCG primes...')
        lcg_for_rsa = LCGOracle(self.lcg_oracle.multiplier, self.lcg_oracle.increment, self.lcg_oracle.modulus, self.seed_hash)
        lcg_for_rsa.deploy_lcg_contract()
        primes_arr = []
        rsa_msg_count = 0
        iteration_limit = 10000
        iterations = 0
        while len(primes_arr) < 8 and iterations < iteration_limit:
            candidate = lcg_for_rsa.get_next(rsa_msg_count)
            rsa_msg_count += 1
            iterations += 1
            if candidate.bit_length() == 256 and isPrime(candidate):
                primes_arr.append(candidate)
                print(f'[RSA]  - Found 256-bit prime #{len(primes_arr)}')
        print('Primes Array: ', primes_arr)
        if len(primes_arr) < 8:
            error_msg = '[RSA] Error: Could not find 8 primes within iteration limit.'
            print('Current Primes: ', primes_arr)
            print(error_msg)
            return error_msg
        n = 1
        for p_val in primes_arr:
            n *= p_val
        phi = 1
        for p_val in primes_arr:
            phi *= p_val - 1
        e = 65537
        if math.gcd(e, phi)!= 1:
            error_msg = '[RSA] Error: Public exponent e is not coprime with phi(n). Cannot generate key.'
            print(error_msg)
            return error_msg
        self.rsa_key = RSA.construct((n, e))
        try:
            with open('public.pem', 'wb') as f:
                pass  # postinserted
        except Exception as e:
                f.write(self.rsa_key.export_key('PEM'))
                    print('[RSA] Public key generated and saved to \'public.pem\'')
                    return 'Public key generated and saved successfully.'
                print(f'[RSA] Error saving key: {e}')
                return f'Error saving key: {e}'
```

We can see the RSA is initalized in similar fashion, so the path to win is as follows:

1. Solve for the LCG primes
2. Use GCD trick to recover the modulus and thus the seed_state
3. Continue feeding `LCG.next` and try to find the RSA primes
4. Craft RSA key pair
5. Profit


## Path to Flag & Script to Win

### Solving for the XOR Primes and Seed

```python
import hashlib, binascii, math

DATA = [
  {"conversation_time": 0, "mode": "LCG-XOR", "plaintext": "Hello", "ciphertext": "e934b27119f12318fe16e8cd1c1678fd3b0a752eca163a7261a7e2510184bbe9"},
  {"conversation_time": 4, "mode": "LCG-XOR", "plaintext": "How are you?", "ciphertext": "25bf2fd1198392f4935dcace7d747c1e0715865b21358418e67f94163513eae4"},
  {"conversation_time": 11, "mode": "LCG-XOR", "plaintext": "Terrible...", "ciphertext": "c9f20e5561acf172305cf8f04c13e643c988aa5ab29b5499c93df112687c8c7c"},
  {"conversation_time": 13, "mode": "LCG-XOR", "plaintext": "Is this a secure channel?", "ciphertext": "3ab9c9f38e4f767a13b12569cdbf13db6bbb939e4c8a57287fb0c9def0288e46"},
  {"conversation_time": 16, "mode": "LCG-XOR", "plaintext": "Yes, it's on the blockchain.", "ciphertext": "3f6de0c2063d3e8e875737046fef079d73cc9b1b7a4b7b94da2d2867493f6fc5"},
  {"conversation_time": 24, "mode": "LCG-XOR", "plaintext": "Erm enable super safe mode", "ciphertext": "787cf6c0be39caa21b7908fcd1beca68031b7d11130005ba361c5d361b106b6d"},
  {"conversation_time": 30, "mode": "LCG-XOR", "plaintext": "Ok, activating now", "ciphertext": "632ab61849140655e0ee6f90ab00b879a3a3da241d4b50bab99f74f169d456db"},
  {"conversation_time": 242, "mode": "RSA", "ciphertext": "680a65364a498aa87cf17c934ab308b2aee0014aee5b0b7d289b5108677c7ad1eb3bcfbcad7582f87cb3f242391bea7e70e8c01f3ad53ac69488713daea76bb3a524bd2a4bbbc2cfb487477e9d91783f103bd6729b15a4ae99cb93f0db22a467ce12f8d56acaef5d1652c54f495db7bc88aa423bc1c2b60a6ecaede2f4273f6dce265f6c664ec583d7bd75d2fb849d77fa11d05de891b5a706eb103b7dbdb4e5a4a2e72445b61b83fd931cae34e5eaab931037db72ba14e41a70de94472e949ca3cf2135c2ccef0e9b6fa7dd3aaf29a946d165f6ca452466168c32c43c91f159928efb3624e56430b14a0728c52f2668ab26f837120d7af36baf48192ceb3002"},
  {"conversation_time": 249, "mode": "RSA", "ciphertext": "6f70034472ce115fc82a08560bd22f0e7f373e6ef27bca6e4c8f67fedf4031be23bf50311b4720fe74836b352b34c42db46341cac60298f2fa768f775a9c3da0c6705e0ce11d19b3cbdcf51309c22744e96a19576a8de0e1195f2dab21a3f1b0ef5086afcffa2e086e7738e5032cb5503df39e4bf4bdf620af7aa0f752dac942be50e7fec9a82b63f5c8faf07306e2a2e605bb93df09951c8ad46e5a2572e333484cae16be41929523c83c0d4ca317ef72ea9cde1d5630ebf6c244803d2dc1da0a1eefaafa82339bf0e6cf4bf41b1a2a90f7b2e25313a021eafa6234643acb9d5c9c22674d7bc793f1822743b48227a814a7a6604694296f33c2c59e743f4106"}
]

def hex_to_bytes(h): return binascii.unhexlify(h)

def rpad32(b):
    return b + b'\x00'*(32-len(b)) if len(b) <= 32 else b[:32]

lcg_outputs = []
for entry in DATA:
    if entry['mode'] != 'LCG-XOR': continue
    ct = hex_to_bytes(entry['ciphertext'])
    pt = entry['plaintext'].encode('utf-8')
    pt_packed = rpad32(pt)
    t_bytes = int(entry['conversation_time']).to_bytes(32, 'big')
    prime_bytes = bytes(x ^ y ^ z for x,y,z in zip(ct, pt_packed, t_bytes))
    lcg_outputs.append(int.from_bytes(prime_bytes, 'big'))
    
print(lcg_outputs)
```

```bash
/6_-_Chain_of_Demands$ python3 solve.py
[72967016216206426977511399018380411256993151454761051136963936354667101207529, 49670218548812619526153633222605091541916798863041459174610474909967699929824, 71280768003266775309606950462778030896956536610993788270598595159221463714935, 52374492464889938543708223275193226150102478572181009159069287723157087096395, 46151066309228226342793435233510111804521449597151473094879900544455543844821, 27616895455297410644582736481740143600211650471053558274523739523026009484149, 20017674779830364175685710279350076931283727675441675047445679766035806574277]
```

Amazing 😊 Each prime is 256 bits.

Now recovering the modulus should be using `gcd` on the primes we just found.

> I've run into a lot of trouble when trying to solve for this so I used the help of my own chat client..

```python
diffs = [lcg_outputs[i+1] - lcg_outputs[i] for i in range(len(lcg_outputs)-1)]
us = [abs(diffs[i+2]*diffs[i] - diffs[i+1]*diffs[i+1]) for i in range(len(diffs)-2)]
m = 0
for u in us:
    if u != 0:
        m = math.gcd(m, u) if m else u
s0,s1,s2 = lcg_outputs[0],lcg_outputs[1],lcg_outputs[2]
a = ((s2 - s1) * pow((s1 - s0) % m, -1, m)) % m
c = (s1 - a*s0) % m
inv_a = pow(a, -1, m)
seed_state = (inv_a * (s0 - c)) % m
```

How does that work you ask?

![](assets/2025-10-25-Flare-On-12-Writeup-Challenge-6/file-20251023153333177.png)
### Solving for the RSA Primes

Now that we have almost all the information including the seed state without knowing the computer name secret we can build our own LCG state machine that for each `_next` does `state = (a*state+c)%m`

```python
class LCG:
    def __init__(self,a,c,m,state): self.a=a; self.c=c; self.m=m; self.state=state
    def next(self):
        self.state = (self.a*self.state + self.c) % self.m
        return self.state
```

and now solving for the RSA primes:

```python
lcg = LCG(a,c,m,seed_state)
primes_for_rsa = []
iters = 0
while len(primes_for_rsa) < 8 and iters < 500000:
    v = lcg.next(); iters += 1
    if v.bit_length() == 256 and is_probable_prime(v):
        primes_for_rsa.append(v)
```

Finally, crafting the private key:

```python
n = 1; phi = 1
for p in primes_for_rsa[:8]:
    n *= p; phi *= (p-1)
e = 65537
d = pow(e, -1, phi)
```

Nice! We have the RSA keys, and now only need to decrypt the RSA.

```python
rsa_entries = [e for e in DATA if e['mode']=='RSA']
for r in rsa_entries:
    ct = hex_to_bytes(r['ciphertext'])
    c_int = int.from_bytes(ct, 'little')
    m_int = pow(c_int, d, n)
    pt_bytes = m_int.to_bytes((m_int.bit_length()+7)//8, 'big') if m_int!=0 else b''
    try:
        s = pt_bytes.decode('utf-8')
    except:
        s = repr(pt_bytes)
    print("Decrypted RSA:", s)
```

```bash
6_-_Chain_of_Demands$ python3 solve.py
Decrypted RSA: Actually what's your email?
Decrypted RSA: It's W3b3_i5_Gr8@flare-on.com
```

I like math, and this challenge was nice, but too easy for a chatbot to understand. Maybe next time, wrap the crypto in assembly obfuscation and make the user understand it himself (spoiler, again).