---
title: "VulnNet: Internal"
date: 2025-3-2
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Medium
---

## Enumeration

```
 nmap -sVC 10.10.45.251 -oA nmap           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-02 16:50 +0545
Nmap scan report for 10.10.45.251 (10.10.45.251)
Host is up (0.17s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5e:27:8f:48:ae:2f:f8:89:bb:89:13:e3:9a:fd:63:40 (RSA)
|   256 f4:fe:0b:e2:5c:88:b5:63:13:85:50:dd:d5:86:ab:bd (ECDSA)
|_  256 82:ea:48:85:f0:2a:23:7e:0e:a9:d9:14:0a:60:2f:ad (ED25519)
111/tcp  open     rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      36991/udp   mountd
|   100005  1,2,3      43419/tcp6  mountd
|   100005  1,2,3      48140/udp6  mountd
|   100005  1,2,3      56363/tcp   mountd
|   100021  1,3,4      37589/tcp6  nlockmgr
|   100021  1,3,4      38051/tcp   nlockmgr
|   100021  1,3,4      46207/udp   nlockmgr
|   100021  1,3,4      46756/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp  open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open     netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
873/tcp  open     rsync       (protocol version 31)
2049/tcp open     nfs         3-4 (RPC #100003)
9090/tcp filtered zeus-admin
Service Info: Host: VULNNET-INTERNAL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: VULNNET-INTERNA, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: vulnnet-internal
|   NetBIOS computer name: VULNNET-INTERNAL\x00
|   Domain name: \x00
|   FQDN: vulnnet-internal
|_  System time: 2025-03-02T12:05:49+01:00
| smb2-time: 
|   date: 2025-03-02T11:05:49
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -19m59s, deviation: 34m37s, median: 0s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.29 seconds

```


We can see nfs shares.
![](Pasted%20image%2020250302165310.png)

We can mount it to our by this.
`sudo mount -v -t nfs 10.10.45.251:/opt/conf mnt`


We can also see this.
![](Pasted%20image%2020250302165541.png)

And this too.
![](Pasted%20image%2020250302165635.png)

Lots of services.

Lets enumerate all of them.
And we can get service.txt.
![](Pasted%20image%2020250302165950.png)
And we can get these.
![](Pasted%20image%2020250302170050.png)
hmm.
![](Pasted%20image%2020250302170132.png)

Lets enumerate further.
And we can find this in redis.conf file from that mount.
![](Pasted%20image%2020250302171223.png)
Now we can do this.
![](Pasted%20image%2020250302171247.png)
And doing keys all gave this.
![](Pasted%20image%2020250302171313.png)
And we got internal flag too.
![](Pasted%20image%2020250302171453.png)

## Foothold

I was new to this services,so i took the help of chatGPT and we could do this.
![](Pasted%20image%2020250302171803.png)

And decoding this gave this.
```
echo "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg==" | base64 -d
Authorization for rsync://rsync-connect@127.0.0.1 with password Hcg3HP67@TW@Bc72v

```

Hmm we got another password.
We can again do this.
`rsync rsync-connect@10.10.45.251::files --password-file=<(echo -n 'Hcg3HP67@TW@Bc72v')`
![](Pasted%20image%2020250302172040.png)

And we can see sys-internal.
`rsync rsync-connect@10.10.45.251::files/sys-internal/`
And files of home directory.
![](Pasted%20image%2020250302172128.png)

We can see .ssh directory.
So lets try to grab a ssh private key.
But its not there.
![](Pasted%20image%2020250302173426.png)

So lets try to add our public key there.
After searching for commands,we could do this.
`rsync -av ./authorized_keys rsync-connect@10.10.45.251::files/sys-internal/.ssh/`

So we will gonna put our public key in a file `authorized_keys` and transfer it to the .ssh directory.

Hmm and we can find user by this.
`rsync rsync-connect@10.10.45.251::files/sys-internal/../`
![](Pasted%20image%2020250302173515.png)

Lets try to do ssh on `sys-internal`.
And we were successful.
![](Pasted%20image%2020250302173626.png)

## Privilege escalation

Lets do privelege escalation.
Lets first run linpeas.sh here.

And we can see this `TeamCity` directory in `/`.
![](Pasted%20image%2020250302174812.png)

Lets enumerate.
And we can see something in port 8111.
![](Pasted%20image%2020250302180614.png)

Lets do port forwarding by ssh and check.
`ssh -i user -L 8111:localhost:8111 sys-internal@10.10.45.251`

Now lets check in our localhost.
![](Pasted%20image%2020250302180832.png)

Hmm but we needs creds.
And logging as super user needs Authentication token.
Hmm let try to find in that teampass directory.
`grep -r -i 'authorization\|token' .`

And we found something.
![](Pasted%20image%2020250302181717.png)

Hmmm.
Lets try it out.
And we could login with this one.
![](Pasted%20image%2020250302181816.png)

Lets see what can we do.
![](Pasted%20image%2020250302181856.png)

Hmm.
![](Pasted%20image%2020250302182119.png)

Interesting.
I guess we have to play around it for some time.
We could do this.
![](Pasted%20image%2020250302190457.png)

So we made this.
![](Pasted%20image%2020250302190642.png)
Lets skip this.

And we were stuck again.
After long time of search,we could edit build step and do like this.
![](Pasted%20image%2020250302190905.png)

Hmm lets select command line.
lets save this.
![](Pasted%20image%2020250302191121.png)
![](Pasted%20image%2020250302191143.png)

Lets try to run it and hope it works.
It worked but we forget gave setuid.
![](Pasted%20image%2020250302191302.png)

Lets try it again and give setuid this time.
And we did it.
![](Pasted%20image%2020250302191747.png)

So we made a new project as administrator.
And filled essential things.
And when it comes to `Build steps`,we change it to use commands and inserted a command that can give us root.
And got root.
![](Pasted%20image%2020250302192133.png)

Again learned so many things.
![](Pasted%20image%2020250302192231.png)

## Done.
Done.
