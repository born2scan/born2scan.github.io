---
layout: post
title:  "IOLI Crackme"
subtitle: "Introduction to disassembly"
date: 2019-03-28
---

[This set of binaries](https://github.com/Maijin/Workshop2015/tree/master/IOLI-crackme) is meant to be patched with Radare2 to accept any password, but here they'll be disassembled and analyzed. Instrumenting them with [Angr](http://angr.io/) proved effective for the first few but the complexity started to grow too fast for it to proceed any further, and in one case alternative approaches (scanning memory for the success string) were thwarted as well.

---


# 1. crackme0x00

```c
int main(void) {
  int isEqual;
  char buffer[24];

  printf("IOLI Crackme Level 0x00\n");
  printf("Password: ");
  scanf("%s", buffer);
  isEqual = strcmp(buffer, "250382");
  if (isEqual == 0) {
    printf("Password OK :)\n");
  } else {
    printf("Invalid Password!\n");
  }
  return 0;
}
```

The password is shown in plaintext in the disassembled source: _250382_{: .spoiler}

---

# 2. crackme0x01

```c
int main(void) {
  int buffer;

  printf("IOLI Crackme Level 0x01\n");
  printf("Password: ");
  scanf("%d", &buffer);
  if (buffer == 0x149a) {
    printf("Password OK :)\n");
  } else {
    printf("Invalid Password!\n");
  }
  return 0;
}
```

Same thing as before, but this time in hex format: _0x149A<sub>hex</sub>⇀5274<sub>dec</sub>_{: .spoiler}

---

# 3. crackme0x02

```c
int main(void) {
  int buffer;

  printf("IOLI Crackme Level 0x02\n");
  printf("Password: ");
  scanf("%d", &buffer);
  if (buffer == 0x52b24) {
    printf("Password OK :)\n");
  } else {
    printf("Invalid Password!\n");
  }
  return 0;
}
```

Once again, plaintext hex to dec: _0x52b24<sub>hex</sub>⇀338724<sub>dec</sub>_{: .spoiler}

---

# 4. crackme0x03

```c
int main(void) {
  int buffer;

  printf("IOLI Crackme Level 0x03\n");
  printf("Password: ");
  scanf("%d", &buffer);
  test(buffer, 0x52b24);
  return 0;
}

void test(int psw1,int psw2) {
  if (psw1 == psw2) {
    shift("Sdvvzrug#RN$$$#=,");
  } else {
    shift("Lqydolg#Sdvvzrug$");
  }
  return;
}

void shift(char *msg) {
  size_t msg_len;
  uint i = 0;
  char buffer[120];

  while (true) {
    msg_len = strlen(msg);
    if (msg_len <= i) break;
    buffer[i] = msg[i] + -3;
    i = i + 1;
  }
  buffer[i] = 0;
  printf("%s\n",buffer);
  return;
}
```

Same as `crackme0x02`, but the code starts to get slightly more nested. The success message is byte shifted so that dynamic symbolic analysis tools such as [angr.io](http://angr.io/) won't be able to search for it easily.

---

# 5. crackme0x04

```c
int main(void) {
  char buffer[120];

  printf("IOLI Crackme Level 0x04\n");
  printf("Password: ");
  scanf("%s", buffer);
  check(buffer);
  return 0;
}

void check(char *psw) {
  size_t psw_len;
  char psw_c;
  uint i = 0;
  int j = 0;
  int n;

  while (true) {
    psw_len = strlen(psw);
    if (psw_len <= i) {
      printf("Password Incorrect!\n");
      return;
    }
    psw_c = psw[i];
    sscanf(&psw_c, "%d", &n);
    j = j + n;
    if (j == 0xf) break;
    i = i + 1;
  }
  printf("Password OK!\n");
  exit(0);
}
```

Things start to get interesting: this time the sum of the password's digits must be equal to _0xf<sub>hex</sub>⇀15<sub>dec</sub>_{: .spoiler}. Valid inputs could be _111111111111111, 555, 96_{: .spoiler} and many more.

---

# 6. crackme0x05

```c
int main(void) {
  char buffer[120];

  printf("IOLI Crackme Level 0x05\n");
  printf("Password: ");
  scanf("%s", buffer);
  check(buffer);
  return 0;
}

void check(char *psw) {
  size_t psw_len;
  char psw_c;
  uint i = 0;
  int j = 0;
  int n;

  while (true) {
    psw_len = strlen(psw);
    if (psw_len <= i) break;
    psw_c = psw[i];
    sscanf(&psw_c, "%d", &n);
    j = j + n;
    if (j == 0x10) {
      parell(psw);
    }
    i = i + 1;
  }
  printf("Password Incorrect!\n");
  return;
}

void parell(char *psw) {
  uint psw_uint;

  sscanf(psw, "%d", &psw_uint);
  if ((psw_uint & 1) == 0) {
    printf("Password OK!\n");
    exit(0);
  }
  return;
}
```

Stems from the same concept that `crackme0x04` is based on, but with an additional twist: the sum of the digits must be equal to _0x10<sub>hex</sub>⇀16<sub>dec</sub>_{: .spoiler} and the number itself must be even _(bitwise **AND** with 1 must be 0)_{: .spoiler}.

---

# 7. crackme0x06

```c
int main(int argc, char *argv[], char *envp[]) {
  char buffer[120];

  printf("IOLI Crackme Level 0x06\n");
  printf("Password: ");
  scanf("%s", buffer);
  check(buffer, envp);
  return 0;
}

void check(char *psw, char *envp) {
  size_t psw_len;
  char psw_c;
  uint i = 0;
  int j = 0;
  int n;

  while (true) {
    psw_len = strlen(psw);
    if (psw_len <= i) break;
    psw_c = psw[i];
    sscanf(&psw_c, "%d", &n);
    j = j + n;
    if (j == 0x10) {
      parell(psw, envp);
    }
    i = i + 1;
  }
  printf("Password Incorrect!\n");
  return;
}

void parell(char *psw, char *envp[]) {
  int dummy_res;
  int i;
  uint n;

  sscanf(psw, "%d", &n);
  dummy_res = dummy(n, envp);
  if (dummy_res != 0) {
    i = 0;
    while (i < 10) {
      if ((n & 1) == 0) {
        printf("Password OK!\n");
        exit(0);
      }
      i = i + 1;
    }
  }
  return;
}

int dummy(int n, int envp) {
  int res;
  int i = 0;

  do {
    if (*(int *)(i * 4 + envp) == 0) {
      return 0;
    }
    res = i * 4;
    i = i + 1;
    res = strncmp(*(char **)(res + envp),"LOLO",3);
  } while (res != 0);
  return 1;
}
```

The types of the `dummy` function are a bit off in this excerpt, but it's quite evident that the sum of the digits must be _0x10<sub>hex</sub>⇀16<sub>dec</sub>_{: .spoiler} and that _an evironment variable named `LOLO`_{: .spoiler} must exist.

```bash
$ LOLO=pwned ./crackme0x06
IOLI Crackme Level 0x06
Password: 88
Password OK!
```
{: .spoiler}

---

# 8. crackme0x07

```c
int main(int argc, char *argv[], char *envp[]) {
  char buffer[120];

  printf("IOLI Crackme Level 0x07\n");
  printf("Password: ");
  scanf("%s", buffer);
  check_1(buffer, envp);
  return 0;
}

void check_1(char *psw, char *envp[]) {
  size_t psw_len;
  int check_3_res;
  char psw_c;
  uint i = 0;
  int j = 0;
  uint n;

  while (true) {
    psw_len = strlen(psw);
    if (psw_len <= i) break;
    psw_c = psw[i];
    sscanf(&psw_c, "%d", &n);
    j = j + n;
    if (j == 0x10) {
      check_2(psw, envp);
    }
    i = i + 1;
  }
  fail();
  check_3_res = check_3(n, envp);
  if (check_3_res != 0) {
    i = 0;
    while ((int) i < 10) {
      if ((n & 1) == 0) {
        printf("wtf?\n");
        exit(0);
      }
      i = i + 1;
    }
  }
  return;
}

void fail(void) {
  printf("Password Incorrect!\n");
  exit(0);
}

int check_3(char *psw,int envp) {
  // ...
}

void check_2(char *psw,int envp) {
  int check_3_res;
  int i;
  char *psw_int_as_char;

  sscanf(psw, "%d", &psw_int_as_char);
  check_3_res = check_3(psw_int_as_char, envp);
  if (check_3_res != 0) {
    i = 0;
    while (i < 10) {
      if (((uint) psw_int_as_char & 1) == 0) {
        if (_DAT_0804a02c == 1) {
          printf("Password OK!\n");
        }
        exit(0);
      }
      i = i + 1;
    }
  }
  return;
}
```

Making sense of the disassembled code was slightly harder this time, since no usual function signatures were to be found. After having pruned libc and system ones, though, determining which ones were written by a human and rearranging them was a far easier task.

Note that the `fail()` call exits the process and is surprisingly placed in the middle of the `check_1` function outside of any conditional block: this means that the rest of the code was probably put there to throw us off even though `check_3` is called before from inside `check_2`. It has been omitted here for brevity since it closely resembles the env var check function we've seen before.

Even though this code is a bit more mind-boggling than the previous binaries - especially before correctly retyping/renaming/rearranging it! - _it works exactly the same as `crackme0x06`_{: .spoiler}.

---

# 9. crackme0x08

```c
int main(int argc, char *argv[], char *envp[]) {
  char buffer[120];

  printf("IOLI Crackme Level 0x08\n");
  printf("Password: ");
  scanf("%s", buffer);
  check(buffer, envp);
  return 0;
}

void check(char *psw,char *envp[]) {
  size_t psw_len;
  char psw_c;
  uint i = 0;
  int j = 0;
  uint n;

  while (true) {
    psw_len = strlen(psw);
    if (psw_len <= i) break;
    psw_c = psw[i];
    sscanf(&psw_c, "%d", &n);
    j = j + n;
    if (j == 0x10) {
      parell(psw, envp);
    }
    i = i + 1;
  }
  fail();
  // ...
}

void fail(void) {
  // ...
}

void parell(char *psw,int envp) {
  int dummy_res;
  int i;
  char *psw_int_as_char;

  sscanf(psw, "%d", &psw_int_as_char);
  dummy_res = dummy(psw_int_as_char, envp);
  if (dummy_res != 0) {
    i = 0;
    while (i < 10) {
      if (((uint)psw_int_as_char & 1) == 0) {
        if (LOL == 1) {
          printf("Password OK!\n");
        }
        exit(0);
      }
      i = i + 1;
    }
  }
  return;
}

int dummy(char *psw, int envp) {
  int res;
  int i = 0;

  do {
    if (*(int *)(i * 4 + envp) == 0) {
      return 0;
    }
    res = i * 4;
    i = i + 1;
    res = strncmp(*(char **)(res + envp), "LOLO", 3);
  } while (res != 0);
  LOL = 1;
  return 1;
}
```

Once again - after some retyping and cleaning up - it looks like this works pretty much like the previous binary. The only exception is that the result of the `dummy()` call is handled via both a return value and the `LOL` variable _(which can be supposed to be a shared or static instance, maybe coming from a common header)_.

---

# 10. crackme0x09

```c
int main(int argc, char *argv[], char *envp[]) {
  char buffer[116];

  printf("IOLI Crackme Level 0x09\n");
  printf("Password: ");
  scanf("%s", buffer);
  check_1(buffer, envp);
  return 0;
}

void check_1(char *psw, char *envp[]) {
  size_t psw_len;
  char psw_c;
  uint i = 0;
  int j = 0;
  uint n;

  while(true) {
    psw_len = strlen(psw);
    if (psw_len <= i) break;
    psw_c = psw[i];
    sscanf(&psw_c, "%d", &n);
    j = j + n;
    if (j == 0x10) {
      check_2(psw, envp);
    }
    i = i + 1;
  }
  fail();
  // ...
}

void check_2(char *psw, char *envp[]) {
  int check_3_res;
  int i;
  uint n;

  sscanf(psw, "%d", &n);
  check_3_res = check_3(n, envp);
  if (check_3_res != 0) {
    i = 0;
    while (i < 10) {
      if ((n & 1) == 0) {
        if (LOL == 1) {
          printf("Password OK!\n");
        }
        exit(0);
      }
      i = i + 1;
    }
  }
  return;
}

int check_3(char *psw, int envp) {
  int iVar1;
  int i = 0;

  do {
    if (*(int *)(i * 4 + envp) == 0) {
      exit(-1);
    }
    iVar1 = i * 4;
    i = i + 1;
    iVar1 = strncmp(*(char **)(iVar1 + envp), "LOLO", 3);
  } while (iVar1 != 0);
  LOL = 1;
  return 1;
}
```

There only are small changes from `crackme0x08` and function signatures weren't immediately identifiable just like in `crackme0x07`: retyping and renaming highlighted that `check_3()` mirrors `dummy()`, and the same solutions set is indeed accepted.