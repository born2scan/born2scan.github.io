---
layout: post
category: writeups
title: "ångstromCTF 2023"
date: 2023-04-27
ctf_categories:
  - misc
  - web
  - crypto
  - rev
  - pwn
---

# Misc

## Physics HW

> _My physics teacher also loves puzzles. Maybe my homework is a puzzle too?_<br>
> _Attachments: physics_hw.png_

🏁 _<FLAG_HERE>_{: .spoiler}

## Admiral Shark

> _I have been snooping on the conversations of my elusive enemies. See if you can help me gather the information I need to defeat them once and for all._<br>
> _Attachments: admiral_shark.pcapng_

🏁 _<FLAG_HERE>_{: .spoiler}

## Simon Says

> _This guy named Simon gave me a bunch of tasks to complete and not a lot of time. He wants to run a unique zoo but needs the names for his animals. Can you help me?_<br>
> _nc challs.actf.co xxxxx_

Connecting to the challenge presented you with a series of prompts like these, the entirety of which you had to solve before a global 3s timeout closed the connection:

```plaintext
Combine the first 3 letters of zebra with the last 3 letters of donkey
> zebkey
Combine the first 3 letters of wombat with the last 3 letters of bear
> womear
[...]
```

With a little help from pwntools to automate the connection this was an easy task:

```python
import re
from pwn import *

conn = remote('challs.actf.co', xxxxx)

while True:
    prompt = conn.recvline().decode('ascii')
    if 'actf{' in prompt:
        print(f"!!! {prompt.strip()}")
        break
    else:
        print(f">>> {prompt.strip()}")

    tokens = re.search(r"Combine the first ([0-9]+) letters of ([a-z]+) with the last ([0-9]+) letters of ([a-z]+)", prompt)
    if len(tokens.groups()) != 4:
        break

    reply = f'{tokens.group(2)[:int(tokens.group(1))]}{tokens.group(4)[-int(tokens.group(3)):]}'
    print(f"<<< {reply}")
    conn.send((reply + '\n').encode('ascii'))

conn.close()
```

```plaintext
[+] Opening connection to challs.actf.co on port xxxxx: Done
>>> Combine the first 3 letters of fish with the last 3 letters of lion
<<< fision
[...]
>>> Combine the first 3 letters of vulture with the last 3 letters of lion
<<< vulion
!!! actf{simon_says_you_win}
[*] Closed connection to challs.actf.co port xxxxx
```

🏁 _actf{simon_says_you_win}_{: .spoiler}

## better me

> _With the power of ARTIFICIAL INTELLIGENCE, I can replace myself!! Ask your questions to this guy, instead._<br>
> _https://xxxxx.actf.co/_

🏁 _<FLAG_HERE>_{: .spoiler}

## Obligatory

> _"angstrom needs a pyjail" - kmh11_<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: jail.py, Dockerfile_

🏁 _<FLAG_HERE>_{: .spoiler}

# Web

## catch me if you can

> _Somebody help!_<br>
> _https://xxxxx.actf.co/_

🏁 _<FLAG_HERE>_{: .spoiler}

## Celeste Speedrunning Association

> _I love Celeste Speedrunning so much!!! It's so funny to watch!!! Here's my favorite site!_<br>
> _https://xxxxx.actf.co/_

🏁 _<FLAG_HERE>_{: .spoiler}

## shortcircuit

> _Bzzt_<br>
> _https://xxxxx.actf.co/_

## directory

> _This is one of the directories of all time, and I would definitely rate it out of 10._<br>
> _https://xxxxx.actf.co/_

🏁 _<FLAG_HERE>_{: .spoiler}

## Celeste Tunnelling Association

> _Welcome to the tunnels!! Have fun!_<br>
> _https://xxxxx.tailxxxxx.ts.net/_<br>
> _Attachments: server.py_

## Hallmark

> _Send your loved ones a Hallmark card! Maybe even send one to the admin 😳._<br>
> _https://xxxxx.actf.co/, https://xxxxx-bot.actf.co/hallmark_<br>
> _Attachments: dist.tar.gz_

🏁 _<FLAG_HERE>_{: .spoiler}

## brokenlogin

> _Talk about a garbage website... I don't think anybody's been able to log in yet! If you find something, make sure to let the admin know._<br>
> _https://xxxxx.actf.co/, https://xxxxx-bot.actf.co/brokenlogin_<br>
> _Attachments: app.py, brokenlogin.js_

🏁 _<FLAG_HERE>_{: .spoiler}

# Crypto

## ranch

> _Caesar dressing is so 44 BC..._<br>
> _`rtkw{cf0bj_czbv_nv'cc_y4mv_kf_kip_re0kyvi_uivjj1ex_5vw89s3r44901831}`_<br>
> _Attachments: ranch.py_

🏁 _<FLAG_HERE>_{: .spoiler}

## impossible

> _Is this challenge impossible?_<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: impossible.py_

🏁 _<FLAG_HERE>_{: .spoiler}

## Lazy Lagrange

> _Lagrange has gotten lazy, but he's still using Lagrange interpolation...or is he?_<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: lazylagrange.py_

🏁 _<FLAG_HERE>_{: .spoiler}

## Royal Society of Arts

> _RSA strikes strikes strikes strikes again again again again!_<br>
> _Attachments: rsa.py, out.txt_

🏁 _<FLAG_HERE>_{: .spoiler}

# Rev

## checkers

> _Attachments: checkers_

🏁 _<FLAG_HERE>_{: .spoiler}

## zaza

> _Bedtime!_<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: zaza_

🏁 _<FLAG_HERE>_{: .spoiler}

## Bananas

> _A friend sent this to me. Can you help me find out what they want?_<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: Elixir.Bananas.beam_

🏁 _<FLAG_HERE>_{: .spoiler}

# Pwn

## queue

> _I just learned about stacks and queues in DSA!_<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: queue_

🏁 _<FLAG_HERE>_{: .spoiler}

## gaga

> _Multipart challenge! Note all use essentially the same Dockerfile. The flags are split among all three challenges. If you are already a pwn expert, the last challenge has the entire flag._<br>
> _nc challs.actf.co xxxxx, xxxx, xxxx_<br>
> _Attachments: gaga0, gaga1, gaga2, Dockerfile_

🏁 _<FLAG_HERE>_{: .spoiler}

## leek

> _nc challs.actf.co xxxxx_<br>
> _Attachments: leek, Dockerfile_

🏁 _<FLAG_HERE>_{: .spoiler}

## widget

> _I seem to have lost my gadgets._<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: widget, Dockerfile_

🏁 _<FLAG_HERE>_{: .spoiler}
