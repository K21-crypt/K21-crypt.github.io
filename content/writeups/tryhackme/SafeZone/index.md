---
title: "SafeZone"
date: 2025-04-17
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Medium
---



## Enumeration
Lets start with the port scan.
```php
nmap -sVC 10.10.91.192 -oA nmap/initial
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-17 18:02 +0545
Nmap scan report for 10.10.91.192 (10.10.91.192)
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:6a:cd:1b:0c:69:a1:3b:6c:52:f1:22:93:e0:ad:16 (RSA)
|   256 84:f4:df:87:3a:ed:f2:d6:3f:50:39:60:13:40:1f:4c (ECDSA)
|_  256 9c:1e:af:c8:8f:03:4f:8f:40:d5:48:04:6b:43:f5:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Whoami?
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.88 seconds
```

Hmmm simple ports are open.
Lets see the port 80.
![](Pasted%20image%2020250417180433.png)

Hmmm lets do directory busting and also use tools like nikto etc.
![](Pasted%20image%2020250417181313.png)

Lets check this features.
So there is `register.php`,`detail.php` and etc.
And there is login page in `/index.php`.
![](Pasted%20image%2020250417181045.png)

I first registered a user and logged in.
![](Pasted%20image%2020250417181238.png)

Hmmm lets check those things.
![](Pasted%20image%2020250417181347.png)
There might be some lfi and rce thing.
there was nothing in `contact.php`and this in `detail.php`.
![](Pasted%20image%2020250417181444.png)
Lets also check the source html too.
Hmm.
![](Pasted%20image%2020250417181536.png)

So there is a page as GET parameter.
But we are not logged in as priveleges user, thats why its saying `You can't access this feature!`.

I have also found `/note.txt`,lets see that.
![](Pasted%20image%2020250417181821.png)

Hmmm.
So we need to access `/home/files/pass/.txt`,lets try doing lfi.
![](Pasted%20image%2020250417182132.png)

## Exploit

Hmmm.
I tried different LFI techniques.
![](Pasted%20image%2020250417182230.png)
But didn't worked.
Lets just try to access that `/home/files/pass.txt`.
But how can we access it.
We don't know the user and there is direct `/home/files/pass.txt`.
Hmmmm.
I am completely stuck now.
Hmmm after seeing writeup for this part,it was this.
![](Pasted%20image%2020250417182711.png)

Really.
![](Pasted%20image%2020250417182856.png)

Wow but okay.
Now i guess we need to login as admin but the password is incomplete.
Lets make a python script for this.

So i made this script with the help of chatGPT.
```python
import requests
import time
import re

url = "http://10.10.91.192/index.php"
username = "admin"
attempts = 0

print("[*] Starting brute-force on admin__admin...")

for i in range(99):  # 00 to 99
    password = f"admin{i:02}admin"
    data = {
        "username": username,
        "password": password,
        "submit": "Submit"
    }

    try:
        response = requests.post(url, data=data, timeout=10)
    except Exception as e:
        print(f"[!] Error with request: {e}")
        continue

    if "Please enter valid login details" in response.text:
        print(f"[-] Tried {password} -> Invalid")
    elif "To many failed" in response.text:
        print("[!] Too many failed attempts, sleeping for 60 seconds...")
        time.sleep(60)
        attempts = 0
        continue
    else:
        print(f"[+] Success! Username: {username}, Password: {password}")
        break

    attempts += 1
    if attempts == 3:
        print("[*] 3 attempts reached. Sleeping 60 seconds...")
        time.sleep(60)
        attempts = 0
```

And we got this.
![](Pasted%20image%2020250417195232.png)

Lets login.
![](Pasted%20image%2020250417195301.png)

And we also can access this.
![](Pasted%20image%2020250417195408.png)

Hmmm and we might also provide `page` parameters and check if we can this or not.
And this worked.
![](Pasted%20image%2020250417195548.png)

Now can we see `/var/log/apache2/access.log`.
![](Pasted%20image%2020250417200401.png)

And cause of my fuzzing, there are lots of requests.
Lets send the php web shell in user-agent and try to execute command.

Now lets add the php web shell in user-agent header and send the request, cause the request will save in `access.log` file, we can now execute command using that php web shell on `/var/log/apache2/access.log` file.
![](Pasted%20image%2020250417201225.png)

And i tried pinging my ip.
![](Pasted%20image%2020250417201257.png)
![](Pasted%20image%2020250417201314.png)

## Foothold

And we succeed.
Lets get the rev shell.
![](Pasted%20image%2020250417201427.png)

Now lets try to escalate our priveleges.
I got the [full tty shell](https://book.hacktricks.wiki/en/generic-hacking/reverse-shells/full-ttys.html) shell.
![](Pasted%20image%2020250417201621.png)
And we got something.
![](Pasted%20image%2020250417201850.png)
Lets read that.
![](Pasted%20image%2020250417201929.png)

We got the hash.
And we could easily crack it using john.
![](Pasted%20image%2020250417202146.png)
![](Pasted%20image%2020250417202222.png)

## Privilege Escalation

Lets see what else we can do.
Hmmm.
![](Pasted%20image%2020250417202327.png)
So we can run id as root.
And we can also change the path variable.
![](Pasted%20image%2020250417202508.png)

but there was full path in `sudo -l`,so we cant abuse that.
![](Pasted%20image%2020250417202835.png)

Hmm lets run linpeas.sh.
After running linpeas and checking what is some odd, we can find this.
![](Pasted%20image%2020250417203433.png)

Hmm lets use ssh to tunnel that port.
`ssh -L 8000:localhost:8000 files@10.10.91.192`

Going in that port, we can see its forbidden.
![](Pasted%20image%2020250417204823.png)

We found this.
![](Pasted%20image%2020250417211405.png)
![](Pasted%20image%2020250417210028.png)

Lets try the usernames and passwords that we have got.
But nothing worked.
Lets see `/pentest.php`.
![](Pasted%20image%2020250417211501.png)

Hmm.
What is this?
Is it like some command panel like thing.
And it was.
we can ping.
![](Pasted%20image%2020250417213041.png)

Lets try to get shell but how cause different thing are blacklisted.
I tried using a nc rev shell but nc is blacklisted.
Lets first make a payload to get reverse shell in `/tmp` and the execute it using that.

I made this.
![](Pasted%20image%2020250417213442.png)

Then, i called it using that panel.
![](Pasted%20image%2020250417213511.png)

And i got the shell.
![](Pasted%20image%2020250417213542.png)
Lets see now how can we became more elevated user.

Now doing `sudo -l`,we can see this.
![](Pasted%20image%2020250417213836.png)

I was just trying and this worked.
![](Pasted%20image%2020250417214159.png)

Hmmm but i need shell.
Lets try to get shell somehow.
So this program is copying the file i guess.

I just tried this and it worked.
![](Pasted%20image%2020250417215227.png)

Now lets see that python program.
Hmm its using sshpass.
![](Pasted%20image%2020250417215327.png)

At last we got the root shell.

## Done

![](Pasted%20image%2020250417215706.png)

And lots of things learned.