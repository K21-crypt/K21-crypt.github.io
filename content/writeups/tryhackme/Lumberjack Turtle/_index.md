---
title: "Lumberjack Turtle"
date: 2025-2-20
draft: false
description: TryHackMe's Medium Room 
Tags:
- TryHackMe
- Linux
- Medium
---

## Enumeration

Lets do the simple port scan.
```
# Nmap 7.95 scan initiated Thu Feb 20 14:37:59 2025 as: /usr/lib/nmap/nmap --privileged -sVC -oA nmap 10.10.26.224
Nmap scan report for 10.10.26.224 (10.10.26.224)
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE     VERSION
22/tcp open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6a:a1:2d:13:6c:8f:3a:2d:e3:ed:84:f4:c7:bf:20:32 (RSA)
|   256 1d:ac:5b:d6:7c:0c:7b:5b:d4:fe:e8:fc:a1:6a:df:7a (ECDSA)
|_  256 13:ee:51:78:41:7e:3f:54:3b:9a:24:9b:06:e2:d5:14 (ED25519)
80/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb 20 14:38:15 2025 -- 1 IP address (1 host up) scanned in 16.48 seconds

```
Hmmm lets do a directory busting.
![](Pasted%20image%2020250220143942.png)
![](Pasted%20image%2020250220150553.png)
And we found something.
![](Pasted%20image%2020250220150625.png)
![](Pasted%20image%2020250220150644.png)
Lets also do further enumeration on it.
![](Pasted%20image%2020250220150833.png)
![](Pasted%20image%2020250220150908.png)
Hmm.
I searched for the vulnerability on internet and found many.
![](Pasted%20image%2020250220152350.png)

And i again searched in metasploit and found this.
![](Pasted%20image%2020250220152328.png)

I used that and set the all necessary options and ran it.
![](Pasted%20image%2020250220164634.png)
And got it.
![](Pasted%20image%2020250220164557.png)


Hmm but we are directly root.
And i also used this to get a good shell.
[[https://book.hacktricks.wiki/en/generic-hacking/reverse-shells/full-ttys.html]]
![](Pasted%20image%2020250220153033.png)

Hmm.
So we are in docker container,i guess.
![](Pasted%20image%2020250220153212.png)
But we couldn't find any flag.
Lets run linpeas.sh.
![](Pasted%20image%2020250220154026.png)
![](Pasted%20image%2020250220154100.png)
![](Pasted%20image%2020250220154127.png)
this one is interesting.
![](Pasted%20image%2020250220154232.png)

And we can find flag1 here.
![](Pasted%20image%2020250220155402.png)

Hmm so there is a setuid on mount and umonut and we need to escape docker container.
After knowing this, i searched for a file under `/dev` to find a file we can use by that setuid.

Doing this, we can find few disk file.
`ls -la /dev`
![](Pasted%20image%2020250220162504.png)

There might contain something there.
Lets do this.
```
mkdir /mnt/test
mount /dev/xvda1 /mnt/test

```

and lets check what is inside.
Its the / directory.
![](Pasted%20image%2020250220163511.png)
Hmmm it might also be the `/` directory of main host.
Lets put our ssh public key on .ssh of root directory.
We can also see this.
![](Pasted%20image%2020250220163947.png)

And we can now successfully login as root by a private key.
![](Pasted%20image%2020250220164053.png)
and we are root.
And we can see something interesting.
![](Pasted%20image%2020250220164233.png)
that `...` directory.
Lets check it out.
And got it.
![](Pasted%20image%2020250220164322.png)

Done.
![](Pasted%20image%2020250220164406.png)

Learned lots of things again.
