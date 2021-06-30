---
layout: post
category: writeups
title: "VolgaCTF 2021"
subtitle: "Qualifiers"
date: 2021-03-28
head_ctf_categories:
  - web
---

# Web

## JWT

> http://172.105.68.62:8080/

The given url lead us to this authentication page:

![jwt_page](/assets/img/VolgaCTF_2021/jwt_page.png)

Once registered, we get an useless page where we are only allowed to "say hi". We noticed a particular cookie and googling the challenge name we found out that it was a JSON Web Token aka JWT.
So using [jwt.io](https://jwt.io) we obtained the following decryption of the token.

![token_decryption](/assets/img/VolgaCTF_2021/jwtio.png)

A known vulnerability of JWT concerns the optional field `jku` which refers to the location (as url) where the private key adopted in the decryption can be found.
The attacker can modify the token providing a maliciuos jku value, and it's also very easy as we can do it directly with [jwt.io](https://jwt.io). As far as we can impose the key location, we can also trick the server with a forged key, which will be used to encrypt the token.
So we created our web server (using php and ngrok), where we exposed a simple file with our key:

```json
{
    "kty": "oct",
    "kid": "HS256",
    "k": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    "alg": "HS256"
}
```

Where `k` stands for the key value in base64 and `kid` is the identifier (the same that appears in the original token).
The malicious token looks like this

![hacktoken](/assets/img/VolgaCTF_2021/hack_token.png)

As you can notice we also changed the `sub` field from `born2scan` to `admin`.
After we set the new token in the cookies we can finally say hi to the server.

![hi](/assets/img/VolgaCTF_2021/hi.gif)

We liked the response.

🏁 __VolgaCTF{jW5_jku_5u85T1TUt10n}__{:.spoiler}
