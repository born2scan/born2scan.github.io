---
layout: post
category: writeups
title:  "AngstromCTF 2019"
date: 2019-04-20
head_message: "These are our writeups for the challenges presented in this year's <a href=\"https://angstromctf.com/\">AngstromCTF</a>."
ctf_categories:
  - misc
  - rev
  - web
  - crypto
---

<script src="{{ "/assets/vendor/highlightjs/build/languages/lisp.min.js" | prepend: site.baseurl }}"></script>

# Misc

## The Mueller Report

> The redacted version of the Mueller report was finally released this week! There's some pretty funny stuff in there, but maybe the report has more beneath the surface.

The attached PDF had corrupt matadata, so the next easy thing to do was running it through `strings`. A hex dump also shows that the flag is located at offset _+0x48E86D7_:

```bash
strings full-mueller-report.pdf | grep "actf{"
hexdump -C full-mueller-report.pdf | grep -A 5 -B 5 "actf{"
```

![hexdump](/assets/img/AngstromCTF_2019/mueller.png)

🏁 _actf{no0o0o0_col1l1l1luuuusiioooon}_{: .spoiler}

## Paper Bin

> defund accidentally deleted all of his math papers! Help recover them from his computer's raw data.

A `paper_bin.dat` file was given, and as usual it did not give many info about itself at first glance:

```bash
$ file paper_bin.dat
paper_bin.dat: data
```

While displaying raw data can be harmful at times, this time it gave us an useful hint:

```bash
$ head -6 paper_bin.dat
��%PDF-1.4
%����
3 0 obj
<<
/Length 2877
/Filter /FlateDecode
```

With the notion of the presence of one or more PDF files, checking how many of them are actually included in the file and extracting them is pretty straightforward:

```bash
$ binwalk paper_bin.dat | grep -v "Unix path" | grep -v "Zlib"

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
222           0xDE            PDF document, version: "1.4"
// 18 more entries...
6770910       0x6750DE        PDF document, version: "1.4"

$ foremost -t pdf -i paper_bin.dat -v
// Extraction takes place...
pdf:= 20

$ pdfgrep "actf\{" ./output/pdf/*.pdf
./output/pdf/00011880.pdf:    actf{proof by triviality}
```

Fix the formatting to match the other flags and submit it right away:

🏁 _actf{proof_by_triviality}_{: .spoiler}

## Lithp

> My friend gave me this program but I couldn't understand what he was saying -<br>
> what was he trying to tell me?<br><br>
> Author: fireholder

```lisp
;LITHP

(defparameter *encrypted* '(8930 15006 8930 10302 11772 13806 13340 11556 12432 13340 10712 10100 11556 12432 9312 10712 10100 10100 8930 10920 8930 5256 9312 9702 8930 10712 15500 9312))
(defparameter *flag* '(redacted))
(defparameter *reorder* '(19 4 14 3 10 17 24 22 8 2 5 11 7 26 0 25 18 6 21 23 9 13 16 1 12 15 27 20))

(defun enc (plain)
    (setf uwuth (multh plain))
    (setf uwuth (owo uwuth))
    (setf out nil)
    (dotimes (ind (length plain) out)
        (setq out (append out (list (/ (nth ind uwuth) -1))))))

(defun multh (plain)
    (cond
        ((null plain) nil)
        (t (cons (whats-this (- 1 (car plain)) (car plain)) (multh (cdr plain))))))

(defun owo (inpth)
    (setf out nil)
    (do ((redth *reorder* (cdr redth)))
        ((null redth) out)
        (setq out (append out (list (nth (car redth) inpth))))))

(defun whats-this (x y)
    (cond
        ((equal y 0) 0)
        (t (+ (whats-this x (- y 1)) x))))

;flag was encrypted with (enc *flag*) to give *encrypted*
```

The code with which we are welcomed, after some research, turned up to be Lisp.

After rolling up our sleeves and getting a grip of Lisp basics,
an analysis of the program shows the following:

* **enc(plain)**

    Is the initial function at which is passed the plaintext flag.<br>
    It then passes the flag to **multh()** and what's returned is further processed throught **owo()**. Berfore returning the resulting list, the sign of every number is inverted;

* **whats-this(x y)**

    This one is just an obfuscation of a simple multiplication between x and y;

* **multh(plain)**

    Every number "x" form **plain** list is multiplied by "1-x" (with **whats-this()**) and the added to a list that's at the end returned;

* **owo(inpth)**

    Scramble **inpth** following indexes of **\*reoder\*** global list

Knowing how the program works, is just a matter of writing a script that does all this backwards.

```python
from string import printable

encrypted = [8930, 15006, 8930, 10302, 11772, 13806, 13340, 11556, 12432, 13340, 10712, 10100, 11556, 12432, 9312, 10712, 10100, 10100, 8930, 10920, 8930, 5256, 9312, 9702, 8930, 10712, 15500, 9312]
reorder = [19, 4, 14, 3, 10, 17, 24, 22, 8, 2, 5, 11, 7, 26, 0, 25, 18, 6, 21, 23, 9, 13, 16, 1, 12, 15, 27, 20]

### create dictonary based on fuzzing fuction for all ascii printable chars

key_dict = { (ord(char)*(ord(char)-1)) : char for char in printable }

### reorder

tmp = [ 0 for i in range(len(encrypted)) ]
for counter, index in enumerate(reorder):
    tmp[index] = encrypted[counter]

### decode

flag = "".join([ key_dict[char] for char in tmp ])
```

🏁 _actf{help_me_I_have_a_lithp}_{: .spoiler}

## Just Letters

> Hope you’ve learned [the alphabet!](https://esolangs.org/wiki/AlphaBeta)<br><br>
> nc NNN.NNN.NNN.NNN PPPPP

The challenge's text pointed to [an EsoLangs page](https://esolangs.org/wiki/AlphaBeta) explaining the AlphaBeta language. It surely isn't the most comfortable tool to use, but it has a nice resemblance with Assembly and thus it's not hard to write once you get the hang of it. Some instruction become much clearer if you peek at the interpreter's source.

Connecting to the given host you were greeted by a prompt, allowing you to enter a single line of AlphaBeta:

```bash
$ nc NNN.NNN.NNN.NNN PPPPP
Welcome to the AlphaBeta interpreter! The flag is at the start of memory. You get one line:
>
```

There were two ways to solve this challenge - as most problems in the programming world, really: the quick way and the right way.

### Quick way:

Read from memory, print out a char, advance to next memory slot. Manually repeat as needed.

```text
GCLSGCLSGCLS...
```

| Instruction | Description                                         |
| ----------- | --------------------------------------------------- |
|    **G**    | Sets register 1 to the memory at the memory pointer |
|    **C**    | Sets register 3 to the value of register 1          |
|    **L**    | Outputs a character to the screen                   |
|    **S**    | Adds 1 to the register                              |
{:.inner-borders}

### (Bonus) Hacky way:

Variant of the following **Right** solution, but iterating over a number given through user input. Discarded because input wasn't really working on the hosted interpreter.

```text
KGCLShxZYSZOZUSSSS
```

| Instruction | Description                                                                         |
| ----------- | ----------------------------------------------------------------------------------- |
|    **K**    | Input a value from the keyboard and store it in register 2                          |
|    **h**    | Subtracts 1 from register 2                                                         |
|    **x**    | Clears register 1                                                                   |
|    **Z**    | Switches in-between modes (starts on memory pointer)                                |
|    **Y**    | Sets the register to 0                                                              |
|    **O**    | If register 1 does not equal register 2, goto the position at the position register |
|    **U**    | Adds 10 to the register                                                             |
{:.inner-borders}

### Right way:

Read from memory, print out a char, advance to next memory slot. Loop as long as a terminator isn't found.

![watch out for that terminator](/assets/img/AngstromCTF_2019/terminator.jpg)

```text
GCLShyZYZOZUSSS
```

| Instruction | Description       |
| ----------- | ----------------- |
|    **y**    | Clears register 2 |
{:.inner-borders}

🏁 _actf{esolangs_sure_are_fun!}_{: .spoiler}

## Scratch It Out

> An oddly yellow cat handed me this message - what could it mean?

An unformatted JSON file was given, and running it through `jq` helps making sense of it:

```json
{
  "targets": [
    {
      "isStage": true,
      "name": "Stage",
      "variables": {
        "`jEk@4|i[#Fk?(8x)AV.-my variable": [
          "my variable",
          75
        ]
      },
      "lists": {
        "DDcejh^KamcM{M3I4TYi": [
          "flag",
          []
        ]
      },
      "broadcasts": {},
      "blocks": {},
      "comments": {},
      "currentCostume": 0,
      "costumes": [
        {
          "assetId": "cd21514d0531fdffb22204e0ec5ed84a",
          "name": "backdrop1",
          "md5ext": "cd21514d0531fdffb22204e0ec5ed84a.svg",
          "dataFormat": "svg",
          "rotationCenterX": 240,
          "rotationCenterY": 180
        }
      ],
      // ...
```

_Being the whole file 7.3KB of JSON, an excerpt will do for the time being._

A yellow cat? Stages, blocks, costumes? _project.json_? **[Scratch](https://scratch.mit.edu/)** it out?

![Well gang, I guess that wraps up the mystery](/assets/img/AngstromCTF_2019/scooby.jpg)

[Scratch's documentation](https://en.scratch-wiki.info/wiki/Scratch_File_Format) confirmed this hypothesis, and since the metadata was indicating that this project was created with the [latest, completely online version of Scratch](https://llk.github.io/scratch-gui/master/), it was just a matter of repacking and uploading it:

```bash
$ cat project.json | jq .meta.semver
"3.0.0"

$ zip project.zip project.json
adding: project.json (deflated 71%)

$ mv project.{zip,sb2}
```

![Scratch](/assets/img/AngstromCTF_2019/scratch.png)

🏁 _actf{Th5_0pT1maL_LANgUaG3}_{: .spoiler}

---

# Rev

## High Quality Checks

> After two break-ins to his shell server, kmh got super paranoid about a third!<br>
> He's so paranoid that he abandoned the traditional password storage method and came up with this monstrosity!<br>
> I reckon he used the flag as the password, can you find it?<br><br>
> Author: Aplet123

The challenge provides a 64bit ELF Executable. To undestand what it does, decompiling it with [Ghidra](https://ghidra-sre.org/) is going to be helpful.

These are the importants bits from main (after formatting):

```c
undefined8 main(void) {
  size_t input_len;
  bool valid;
  char input[24];

  puts("Enter your input:");
  __isoc99_scanf(&DAT_00400b96,input);
  input_len = strlen(input);
  if (input_len < 0x13) {
    puts("Flag is too short.");
  }
  else {
    valid = check(input);
    if ((int)valid == 0) {
      puts("That\'s not the flag.");
    }
    else {
      puts("You found the flag!");
    }
  }
}
```

After the input validation part, the only interesting function is **"check(input)"**.

```c
bool check(char *input) {
int iVar1;

  iVar1 = d(input + 0xc);
  if ((((((iVar1 != 0) && (iVar1 = v((ulong)(uint)(int)*input), iVar1 != 0)) &&
        (iVar1 = u((ulong)(uint)(int)input[0x10],(ulong)(uint)(int)input[0x11],
                   (ulong)(uint)(int)input[0x11]), iVar1 != 0)) &&
       ((iVar1 = k((ulong)(uint)(int)input[5]), iVar1 == 0 &&
        (iVar1 = k((ulong)(uint)(int)input[9]), iVar1 == 0)))) &&
      ((iVar1 = w(input + 1), iVar1 != 0 &&
       ((iVar1 = b(input,0x12), iVar1 != 0 && (iVar1 = b(input,4), iVar1 != 0)))))) &&
     ((iVar1 = z(input,0x6c), iVar1 != 0 && (iVar1 = s(input), iVar1 != 0)))) {
    return true;
  }
  return false;
}
```

At first it might be a little bewildering but looking at the flow of things, it's just a bunch of checks that in the end returns either true or false.

Challenges like this might easily be solved with [Symbolic Execution](https://en.wikipedia.org/wiki/Symbolic_execution) if they don't scale too much resulting in a [Path Explosion](https://en.wikipedia.org/wiki/Symbolic_execution#Path_explosion).

One awesome tool that does Symbolic Execution and much more is [**"angr"**](http://angr.io).

Here's the python script used to solve this challenge with angr.

```python
import angr

p = angr.Project('./high_quality_checks', auto_load_libs=False)
state = p.factory.entry_state()
sm = p.factory.simulation_manager(state)
destinationAddr = HEX_ADDRESS # Where is executed "puts("You found the flag!");"
sm.explore(find=destinationAddr)

if len(sm.found) > 0:
    for targetstate in sm.found:
        print(targetstate.posix.dumps(0))
```

🏁 _actf{fun_func710n5}_{: .spoiler}

---

# Web

## No Sequels

> The prequels sucked, and the sequels aren't much better, but at least we always have the original trilogy.

The description pointed to a webpage containing a login form and the snippet of code powering it:

![No Sequels 1](/assets/img/AngstromCTF_2019/no_sequels_1.jpg)

```js
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
...
router.post('/login', verifyJwt, function (req, res) {
    // monk instance
    var db = req.db;
    var user = req.body.username;
    var pass = req.body.password;
    if (!user || !pass){
        res.send("One or more fields were not provided.");
    }
    var query = {
        username: user,
        password: pass
    }
    db.collection('users').findOne(query, function (err, user) {
        if (!user){
            res.send("Wrong username or password");
            return
        }
        res.cookie('token', jwt.sign({name: user.username, authenticated: true}, secret));
        res.redirect("/site");
    });
});
```

The code showed that neither the user input was sanitized, nor was the encoding of the request forced _(Express tries to parse that itself unless differently instructed)_. The following JSON request could be used to trick the webserver into injecting conditionals inside the MongoDB query:

```json
{
  "username": {"$gt": ""},
  "password": {"$gt": ""}
}
```

_Instead of `{"gt": ""}` many other variations could be used: `{"$exists": true}`, `{"$not": {"$size": 0}}`, `{"$ne": null}`..._

[Insomnia](https://github.com/getinsomnia/insomnia) is a handy tool for working with HTTP requests; remember to extract the session JWT from the browser's `token` cookie and apply it, though.

![Insomnia](/assets/img/AngstromCTF_2019/insomnia.png)

🏁 _actf{no_sql_doesn't_mean_no_vuln}_{: .spoiler}

---

# Crypto

## Classy Cipher (20 pts)

> Every CTF starts off with a Caesar cipher, but we're more classy.<br><br>
> Author: defund

```python
from secret import flag, shift

def encrypt(d, s):
    e = ''
    for c in d:
        e += chr((ord(c)+s) % 0xff)
    return e

assert encrypt(flag, shift) == ':<M?TLH8<A:KFBG@V'
```

This is nothing more than a regular implementation of a caesar cipher.
Knowing the flags format ( **"actf{...}"** ), displacement can be easily acquired subtracting any known character with its encrypted one.

```python
def decrypt(d, s):
    e = ''
    for c in d:
        e += chr((ord(c)-s) % 0xff)
    return e

enc = ':<M?TLH8<A:KFBG@V'
flag = decrypt(enc, ord(':')-ord('a'))
```

🏁 _actf{so_charming}_{: .spoiler}

## Really Secure Algorithm (30 pts)

> I found this flag somewhere when I was taking a walk,<br>
> but it seems to have been encrypted with this Really Secure Algorithm!<br><br>
> Author: lamchcl

```text
p = 8337989838551614633430029371803892077156162494012474856684174381868510024755832450406936717727195184311114937042673575494843631977970586746618123352329889
q = 7755060911995462151580541927524289685569492828780752345560845093073545403776129013139174889414744570087561926915046519199304042166351530778365529171009493
e = 65537
c = 7022848098469230958320047471938217952907600532361296142412318653611729265921488278588086423574875352145477376594391159805651080223698576708934993951618464460109422377329972737876060167903857613763294932326619266281725900497427458047861973153012506595691389361443123047595975834017549312356282859235890330349
```

As the variables names suggest, this is RSA.

For deciphering the message is needed the private key that's not so easily given.
But it can be generated since everything required is provided.

For working with RSA, there's an awesome tool: [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)

```bash
./RsaCtfTool.py -p $P -q $Q -e $E --uncipher $C
```

Remove the "\x00" padding, et voilà!

🏁 _actf{really_securent_algorithm}_{: .spoiler}

## Half and Half (50 pts)

> Mm, coffee. Best served with half and half!<br><br>
> Author: defund

```python
from secret import flag

def xor(x, y):
  o = ''
  for i in range(len(x)):
    o += chr(ord(x[i])^ord(y[i]))
  return o

assert len(flag) % 2 == 0

half = len(flag)//2
milk = flag[:half]
cream = flag[half:]

assert xor(milk, cream) == '\x15\x02\x07\x12\x1e\x100\x01\t\n\x01"'
```

This challenge code, halves the flag and xor together the two parts. The goal is to recover the initial flag from the given result of the xor.

The length of the flag is just twice the length of the resulting xor. That is 24 (look out for those not hex encoded chars).

Being xor a function that, if applied twice with the same value cancels itself: _`A ⨁ B ⨁ B = A`_, to start off, flag format characters ( **"actf{}"** ) can be used to retrieve a few others.

```text
a c t f { ? ? ? ? ? ? _
t a s t e ? ? ? ? ? ? }

a c t f { ? ? ? ? ? ? _ t a s t e ? ? ? ? ? ? }
```

As the challenge description suggests, the word **coffee** can be tried seeing that it fits in and would also make sense with the following word **taste**.

That was indeed the right word, so the entire flag is revealed.

```text
a c t f { c o f f e e _
t a s t e s _ g o o d }

🏁 actf{coffee_tastes_good}
```

{: .spoiler}
