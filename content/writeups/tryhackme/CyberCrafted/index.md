---
title: "CyberCrafted"
date: 2025-05-11
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Medium
---

## Enumeration

```
nmap -sVC 10.10.114.176 -oA nmap/nmap            
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-11 00:41 +0545
Nmap scan report for 10.10.114.176 (10.10.114.176)
Host is up (0.17s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE   VERSION
22/tcp   open     ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:36:ce:b9:ac:72:8a:d7:a6:b7:8e:45:d0:ce:3c:00 (RSA)
|   256 e9:e7:33:8a:77:28:2c:d4:8c:6d:8a:2c:e7:88:95:30 (ECDSA)
|_  256 76:a2:b1:cf:1b:3d:ce:6c:60:f5:63:24:3e:ef:70:d8 (ED25519)
80/tcp   open     http      Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Did not follow redirect to http://cybercrafted.thm/
|_http-server-header: Apache/2.4.29 (Ubuntu)
2041/tcp filtered interbase
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.94 seconds
```

Lets add `cybercrafted.thm` in `/etc/hosts` and access port 80.
![](Pasted%20image%2020250511004421.png)

Hmm nothing.
Lets see source.
![](Pasted%20image%2020250511004509.png)

Hmm so there are other sub domains.
Lets try to get that and also lets try to do directory busting.
![](Pasted%20image%2020250511004659.png)

Hmm.
`/secret`
But there was only few images.
![](Pasted%20image%2020250511004732.png)

Lets now do sub domain enumeration.
![](Pasted%20image%2020250511005240.png)

Hmm lets put those in `/etc/hosts`.
There is a login page in admin sub domain.
![](Pasted%20image%2020250511005440.png)
And store sub domain has forbidden.
![](Pasted%20image%2020250511005611.png)

Lets do directory bruteforcing on `admin.cybercrafted.thm`.
![](Pasted%20image%2020250511005807.png)

Hmm `command.png`, So is there command injection or something.
Hmm.
![](Pasted%20image%2020250511005918.png)

So its a php site, there is `login.php`.
Lets also try to find directories with extensions like php,txt,etc.
And there was also `panel.css`, and we got it.
![](Pasted%20image%2020250511010208.png)
But it redirect us to login page.
Hmm.
I guess it is upcoming thing for command execution.
Hmm but for now we have to be logged in somehow.

Hmmm lets also check that forbidden sub domain store.
![](Pasted%20image%2020250511011027.png)

Hmm so there is `/search.php`.
Lets check that out.
![](Pasted%20image%2020250511011120.png)

Hmm searching thing.
![](Pasted%20image%2020250511011203.png)

## Exploit

Hmmm.
Is it command injection thing?
Hmmm lets try some.
But didn't worked.

Lets see that in burp.
![](Pasted%20image%2020250511011501.png)

Hmm.
Lets also test sql injection.
I used sqlmap for that.
I captured the request with burp.
`sqlmap -r "$(pwd)/req.txt" -p search --dump --batch`

And it worked.
![](Pasted%20image%2020250511013342.png)
![](Pasted%20image%2020250511013404.png)

Hmm so we got the flag and creds.

We got the username and password hash.
![](Pasted%20image%2020250511013609.png)

```md
User:xXUltimateCreeperXx
Pass:diamond123456789
```

## Foothold

Lets try to login on that previous login page with this cred.
![](Pasted%20image%2020250511014312.png)
We logged in.
Hmm so we can execute command from here i guess.
![](Pasted%20image%2020250511014359.png)

We can get the easy reverse shell.
And we can get `id_rsa` in `/home/xxultimatecreeperxx/.ssh/id_rsa`.
![](Pasted%20image%2020250511031350.png)

We can then easily crack the passphrase.
![](Pasted%20image%2020250511031434.png)

`creepin2006`

## Privilege Escalation

After logging in.
We can run linpeas.
![](Pasted%20image%2020250511032151.png)

Hmm so cybercrafted is running tar something in cron.
We might use it.
Lets see.
After checking `/opt/minecraft/`, we can see these.
![](Pasted%20image%2020250511032831.png)

Hmm. we got the plugin and a log file with the password of `cybercrafted`.
![](Pasted%20image%2020250511033009.png)
`JavaEdition>Bedrock`

So now we are cybercrafted.

And now doing `sudo -l` gave this.
![](Pasted%20image%2020250511033148.png)

Hmm.
`/usr/bin/screen -r cybercrafted` as root.

I tried different things and tried to understand but didn't succeed to escalate my priveleges.
After doing some research, i got [this](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-screen-privilege-escalation/).
![](Pasted%20image%2020250511035254.png)

It was small, we just need to do
`ctrl+a+c` after running screen command as root.
![](Pasted%20image%2020250511035417.png)

And we will be showed up with sh root shell.
And we are root again.
![](Pasted%20image%2020250511035511.png)

## Done

And done.
In this room, we learned more new thing like privilege escalation with screen command with sudo and also helped to sharp my recon skills.
![](Pasted%20image%2020250511040046.png)
