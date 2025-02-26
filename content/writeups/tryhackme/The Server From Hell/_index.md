---
title: "The Server From Hell"
date: 2025-2-27
draft: false
description: TryHackMe's Good Room
Tags:
- TryHackMe
- Linux
- Medium
---


**Lets start with enumeration.**
**Port scan**

![](Pasted%20image%2020250226174343.png)

And we can see this.
![](Pasted%20image%2020250226174401.png)

Lots of ports.

Lets do this.
`nmap -p 1-100 -sV 10.10.193.92`

We can find this.
```
nmap -p 1-100 --script=banner 10.10.193.92
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-26 17:43 +0545
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 7.50% done; ETC: 17:43 (0:00:00 remaining)
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 11.50% done; ETC: 17:43 (0:00:15 remaining)
Nmap scan report for 10.10.193.92
Host is up (0.22s latency).

PORT    STATE SERVICE
1/tcp   open  tcpmux
| banner: 550 12345 00000000000000000000000000000000000000000000000000000
|_00
2/tcp   open  compressnet
| banner: 550 12345 00000000000000000000000000000000000000000000000000000
|_00
3/tcp   open  compressnet
| banner: 550 12345 00000000000000000000000000000000000000000000000000000
|_00
4/tcp   open  unknown
| banner: 550 12345 00000000000000000000000000000000000000000000000000000
|_00
5/tcp   open  rje
| banner: 550 12345 00000000000000000000000000000000000000000000000000000
|_00
6/tcp   open  unknown
| banner: 550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff
|_00
7/tcp   open  echo
| banner: 550 12345 0fffffffffffff777778887777777777cffffffffffffffffffff
|_00
8/tcp   open  unknown
| banner: 550 12345 0fffffffffff8000000000000000008888887cfcfffffffffffff
|_00
9/tcp   open  discard
| banner: 550 12345 0ffffffffff80000088808000000888800000008887ffffffffff
|_00
10/tcp  open  unknown
| banner: 550 12345 0fffffffff70000088800888800088888800008800007ffffffff
|_00
11/tcp  open  systat
| banner: 550 12345 0fffffffff000088808880000000000000088800000008fffffff
|_00
12/tcp  open  unknown
| banner: 550 12345 0ffffffff80008808880000000880000008880088800008ffffff
|_00
13/tcp  open  daytime
| banner: 550 12345 0ffffffff000000888000000000800000080000008800007fffff
|_00
14/tcp  open  unknown
| banner: 550 12345 0fffffff8000000000008888000000000080000000000007fffff
|_00
15/tcp  open  netstat
| banner: 550 12345 0ffffff70000000008cffffffc0000000080000000000008fffff
|_00
16/tcp  open  unknown
| banner: 550 12345 0ffffff8000000008ffffff007f8000000007cf7c80000007ffff
|_00
17/tcp  open  qotd
| banner: 550 12345 0fffff7880000780f7cffff7800f8000008fffffff80808807fff
|_00
18/tcp  open  msp
| banner: 550 12345 0fff78000878000077800887fc8f80007fffc7778800000880cff
|_00
19/tcp  open  chargen
| banner: 550 12345 0ff70008fc77f7000000f80008f8000007f0000000000000888ff
|_00
20/tcp  open  ftp-data
| banner: 550 12345 0ff0008f00008ffc787f70000000000008f000000087fff8088cf
|_00
21/tcp  open  ftp
| banner: 550 12345 0f7000f800770008777 go to port 12345 80008f7f700880cf
|_00
22/tcp  open  ssh
| banner: 550 12345 0f8008c008fff8000000000000780000007f800087708000800ff
|_00
23/tcp  open  telnet
| banner: 550 12345 0f8008707ff07ff8000008088ff800000000f7000000f800808ff
|_00
24/tcp  open  priv-mail
| banner: 550 12345 0f7000f888f8007ff7800000770877800000cf780000ff00807ff
|_00
25/tcp  open  smtp
| banner: 550 12345 0ff0808800cf0000ffff70000f877f70000c70008008ff8088fff
|_00
26/tcp  open  rsftp
| banner: 550 12345 0ff70800008ff800f007fff70880000087f70000007fcf7007fff
|_00
27/tcp  open  nsw-fe
| banner: 550 12345 0fff70000007fffcf700008ffc778000078000087ff87f700ffff
|_00
28/tcp  open  unknown
| banner: 550 12345 0ffffc000000f80fff700007787cfffc7787fffff0788f708ffff
|_00
29/tcp  open  msg-icp
| banner: 550 12345 0fffff7000008f00fffff78f800008f887ff880770778f708ffff
|_00
30/tcp  open  unknown
| banner: 550 12345 0ffffff8000007f0780cffff700000c000870008f07fff707ffff
|_00
31/tcp  open  msg-auth
| banner: 550 12345 0ffffcf7000000cfc00008fffff777f7777f777fffffff707ffff
|_00
32/tcp  open  unknown
| banner: 550 12345 0cccccff0000000ff000008c8cffffffffffffffffffff807ffff
|_00
33/tcp  open  dsp
| banner: 550 12345 0fffffff70000000ff8000c700087fffffffffffffffcf808ffff
|_00
34/tcp  open  unknown
| banner: 550 12345 0ffffffff800000007f708f000000c0888ff78f78f777c008ffff
|_00
35/tcp  open  priv-print
| banner: 550 12345 0fffffffff800000008fff7000008f0000f808f0870cf7008ffff
|_00
36/tcp  open  unknown
| banner: 550 12345 0ffffffffff7088808008fff80008f0008c00770f78ff0008ffff
|_00
37/tcp  open  time
| banner: 550 12345 0fffffffffffc8088888008cffffff7887f87ffffff800000ffff
|_00
38/tcp  open  rap
| banner: 550 12345 0fffffffffffff7088888800008777ccf77fc777800000000ffff
|_00
39/tcp  open  rlp
| banner: 550 12345 0fffffffffffffff800888880000000000000000000800800cfff
|_00
40/tcp  open  unknown
| banner: 550 12345 0fffffffffffffffff70008878800000000000008878008007fff
|_00
41/tcp  open  graphics
| banner: 550 12345 0fffffffffffffffffff700008888800000000088000080007fff
|_00
42/tcp  open  nameserver
| banner: 550 12345 0fffffffffffffffffffffc800000000000000000088800007fff
|_00
43/tcp  open  whois
| banner: 550 12345 0fffffffffffffffffffffff7800000000000008888000008ffff
|_00
44/tcp  open  mpm-flags
| banner: 550 12345 0fffffffffffffffffffffffff7878000000000000000000cffff
|_00
45/tcp  open  mpm
| banner: 550 12345 0ffffffffffffffffffffffffffffffc880000000000008ffffff
|_00
46/tcp  open  mpm-snd
| banner: 550 12345 0ffffffffffffffffffffffffffffffffff7788888887ffffffff
|_00
47/tcp  open  ni-ftp
| banner: 550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff
|_00
48/tcp  open  auditd
| banner: 550 12345 00000000000000000000000000000000000000000000000000000
|_00
49/tcp  open  tacacs
| banner: 550 12345 00000000000000000000000000000000000000000000000000000
|_00
50/tcp  open  re-mail-ck
| banner: 550 12345 00000000000000000000000000000000000000000000000000000
|_00
51/tcp  open  la-maint
|_banner: SIP/2.0 200 OK\x0D\x0AiServer: NetSapiens SiPBx 1-1205c
52/tcp  open  xns-time
|_banner: E000vSc0C0A0000MProtocole non support?e de l'interface 65363
53/tcp  open  domain
|_banner: 220 _eXFH NTMail (v72386538/XKNFYpl) ready for ESMTP transfer
54/tcp  open  xns-ch
| banner: yetcavdc\x00\x00\x02\x97v\x8BT\xADy\xE3\xAF\x87\xEB\xAA\x1A\x19
|_\xBA\xCFA\xE0\x16\xA22l\xF3\xCF\xF4\x8E<D\x83\xC8\x8DQEo\x90\x95#3\x...
55/tcp  open  isi-gl
|_banner: SSH-998877-VShell_6_1843 VShell\x0D?
56/tcp  open  xns-auth
| banner: HTTP/1.0 918 w\x0D\x0AServer: IP_SHARER WEB bK\x0D\x0AWWW-Authe
|_nticate: Basic realm="MR814v2"
57/tcp  open  priv-term
| banner: Rapture Runtime Environment v645494935 -- (c) 7-- Iron Realms E
|_ntertainment
58/tcp  open  xns-mail
| banner: HTTP/1.0 200 OK\x0D\x0ACache-Control: no-cache\x0D\x0AContent-T
|_ype: text/html\x0D\x0AContent-Length: 7r\x0AServer: MediaMallServer/w
59/tcp  open  priv-file
| banner: HTTP/1.1 460 r\x0D\x0AConnection: close\x0D\x0ADate: y\x0D\x0AC
|_ache-Control: no-cache\x0D\x0APragma: no-cache\x0D\x0AContent-Type: ...
60/tcp  open  unknown
|_banner: RTSP/1.0 405 Method Not Allowed\x0D\x0ACSeq: 42
61/tcp  open  ni-mail
| banner: HTTP/1.1 200 f\x0D\x0AServer: Allegro-Software-RomPager/yYm\x0D
|_\x0Ab<TITLE>RICOH FAX i/ RICOH Network Printer
62/tcp  open  acas
|_banner: \xFF\xFF\xFF\xFF\x01disconnect
63/tcp  open  via-ftp
|_banner: HTTP/1.1 814 s\x0D\x0ADate: s\x0D\x0AServer: SAMBAR
64/tcp  open  covia
|_banner: HTTP/1.0 200 OK\x0AServer: stats.mod/0MjVWDCN
65/tcp  open  tacacs-ds
| banner: \x01\x0300luiicqvh0000reojocvh\x8F\xFAv\xF5\x11*\x09Macintosh\x
|_01\x06AFP3.1k\x09DHCAST128
66/tcp  open  sqlnet
| banner: HTTP/1.470 j\x0D\x0AServer: Polycom SoundPoint IP Telephone HTT
|_Pd
67/tcp  open  dhcps
| banner: HTTP/1.0 200 OK\x0D\x0AContent-type: text/html\x0D\x0AContent-E
|_ncoding: gzip\x0D\x0ACache-Control: max-age=600, must-revalidate\x0D...
68/tcp  open  dhcpc
| banner: 000b\xFFSMBr0000\x88\x01@00000000000000@\x0600\x010\x11\x070n\x
|_0A0\x010\x04\x110000\x0100000\xFD\xE300
69/tcp  open  tftp
| banner: HTTP/1.1 500 ( Die Anforderung wurde vom HTTP-Filter zur\xC3\xB
|_Cckgewiesen. Wenden Sie sich an den ISA Server-Administrator.  )
70/tcp  open  gopher
|_banner: +OK popserver 813257030 pop3 server ready
71/tcp  open  netrjs-1
| banner: \xFF\xFD\x01\xFF\xFD\x1F\xFF\xFD!\xFF\xFB\x01\xFF\xFB\x03bkmPW 
|_login:
72/tcp  open  netrjs-2
|_banner: 000*\x03\x01\x80\x100w\xC9megwerwlsnmblntgwvdw
73/tcp  open  netrjs-3
| banner: HTTP/1.0 200 OK\x0D\x0AContent-type: text/html; charset=utf-8\x
|_0D\x0AContent-Length: 204\x0D\x0A\x0D\x0A<!DOCTYPE html PUBLIC "-//W...
74/tcp  open  netrjs-4
|_banner: HTTP/1.890 h\x0D\x0AServer: Snug/rRFt
75/tcp  open  priv-dial
|_banner: HTTP/1.0 445 a\x0D\x0AServer: DesktopAuthority/061237862
76/tcp  open  deos
|_banner: x01
77/tcp  open  priv-rje
| banner: HTTP/1.0 281 s\x09<title>Strongdc++ webserver - Login Page</tit
|_le>
78/tcp  open  vettcp
| banner: HTTP/1.1 302 Object Moved\x0D\x0AServer: NS_oLhhX\x0D\x0ALocati
|_on: http://XnPCjoiTH/wts
79/tcp  open  finger
| banner: \xFF\xFB\x01\xFF\xFB\x03\x0D\x0A\x0D\x0A\x0D\x0A +-+\x0D\x0A +|
|_ Cyclades-PR4000: CyROS  V_66831  (u)     |
80/tcp  open  http
| banner: HTTP/1.0 699 y\x0D\x0AServer: NT40\x0D\x0Ak<title>NTbRB - Multi
|_protocol chat tool</title></head><body><BR><BR><center><b>NT4.0 Netw...
81/tcp  open  hosts2-ns
| banner: SIP/2.0 u\x0D\x0AServer: Sip EXpress router (07407519- (3137032
|_))
82/tcp  open  xfer
|_banner: \x8000$000\x01L\xB4!\xD2000000\x05\x02000000000000000\x040000
83/tcp  open  mit-ml-dev
| banner: E000\x84SFATAL0C0A0000Munsupported frontend protocol 65363.1977
|_8: server supports 1.0 to 3.00Fpostmaster.c0L14540RProcessStartupPac...
84/tcp  open  ctf
| banner: HTTP/1.0 501 Unsupported method ('GET')\x0D\x0AServer: BaseHTTP
|_/41306486 Python/IVRK
85/tcp  open  mit-ml-dev
| banner: HTTP/1.1 200 OK\x0D\x0AgServer: Wapapi/NpZrS-gKo\x0D\x0AContent
|_-Type: text/html\x0D\x0AContent-Length: 7r\x0A\x0D\x0A<html>\x0D\x0A...
86/tcp  open  mfcobol
| banner: 220 FTP server ready.\x0D\x0A530 USER and PASS required\x0D\x0A
|_530 USER and PASS required
87/tcp  open  priv-term-l
| banner: 000\x81\x81xa0\x03\x02\x01\x05\xA1\x03\x02\x01\x1E\xA2\x11\x18\
|_x0F5{14}Z\xA4\x11\x18\x0F10146202263270Z\xA5x02?:\x03tpt|\x02fg|\x01...
88/tcp  open  kerberos-sec
| banner: SIP/2.0 500 Server Internal Error\x0D\x0Ay\x0D\x0AUser-Agent: B
|_T Home Hub
89/tcp  open  su-mit-tg
| banner: \x020]\x02000000\x010h000\x01\x0F\xFF\x810\x97000a0\x04000\x01\
|_x01+3900\x01|v43410NI Master0AMX Corp.0\x06\x0C\xC0\xA8"D\x05'0`\x9F...
90/tcp  open  dnsix
| banner: HTTP/1.1 200 a\x0D\x0ASERVER: Linux/aGJmOkciQ, UPnP/0, MediaTom
|_b/zkCwMThR
91/tcp  open  mit-dov
| banner: PRLT\x060\x070cetm (ifl, 41 ofh 7264 50:77:33)00000000000000000
|_000
92/tcp  open  npp
| banner: HTTP/1.0 200 OK\x0D\x0ACache-Control: no-store\x0D\x0APragma: n
|_o-cache\x0D\x0ACache-Control: no-cache\x0D\x0AX-Bypass-Cache: Applic...
93/tcp  open  dcp
| banner: HTTP/1.852 u\x0D\x0AServer: Oracle_Web_Listener/2AdvancedEditio
|_n
94/tcp  open  objcall
|_banner: HTTP/1.1 406 Not Acceptable\x0D\x0AServer: Phex 14228
95/tcp  open  supdup
| banner: HTTP/1.0 504 Gateway Timeout\x0D\x0AContent-Length: 237\x0D\x0A
|_s<p>The proxy server did not receive a timely response\x0Afrom the u...
96/tcp  open  dixie
| banner: NOTICE AUTH :*** Checking Ident\x0D\x0ANOTICE AUTH :*** Got ide
|_nt response
97/tcp  open  swift-rvf
|_banner: update/1.4.2
98/tcp  open  linuxconf
| banner: HTTP/0.0 400 Bad request\x0D\x0AServer: Aos HTTP Server/Vk\x0D\
|_x0AHTTP/0.0 400 Bad request\x0D\x0AServer: Aos HTTP Server/TzefNq\x0...
99/tcp  open  metagram
|_banner: 220 ddJc(7UzbtWty) FTP server (EPSON \xEA\xAE{q/) ready.
100/tcp open  newacct
| banner: HTTP/1.0 200 OK\x0D\x0AContent-Type: text/html\x0D\x0A\x0D\x0A<
|_html>\x0A<body>\x0A<ul><li>\x0A<i>com.apple.KernelEventAgent</i>

Nmap done: 1 IP address (1 host up) scanned in 19.23 seconds

```

and one interesting,
![](Pasted%20image%2020250226175011.png)

Hmm but we need user and pass.
And another important thing.
![](Pasted%20image%2020250226175506.png)

Lets see what can we do.
Lets try to mount the nfs share to us.
`showmount -e 10.10.193.92`
`mkdir nfs`
`sudo mount -t nfs 10.10.193.92:/home/nfs nfs`

And we can see this.
![](Pasted%20image%2020250226180041.png)
And we again need a password.
![](Pasted%20image%2020250226180115.png)
Can we crack?
Lets try it.
And we can crack it.
![](Pasted%20image%2020250226180327.png)
`zxcvbnm`

Lets continue.
![](Pasted%20image%2020250226180410.png)
And we might also use this username in that previous ftp.
And we got our first flag.
`thm{h0p3_y0u_l1k3d_th3_f1r3w4ll}`

Hmm so we got the `id_rsa`,username and many more with this hint.
![](Pasted%20image%2020250226180700.png)

Hmm so ssh port might be in that range.
![](Pasted%20image%2020250226181150.png)
its not possible.
So lets again grab banner in that range.
`nmap -p 2500-4500 --script=banner 10.10.193.92`

After that,I tried to do ssh in every port by this script.
```
#!/bin/bash

USER="hades"
HOST="10.10.233.105"
PRIVATE_KEY="id_rsa"

# Loop through ports 2500 to 4500
for PORT in {2500..4500}; do
    echo "Attempting to login to port $PORT..."
    ssh -i $PRIVATE_KEY -p $PORT $USER@$HOST "echo 'Connected on port $PORT'"
    
    if [ $? -eq 0 ]; then
        echo "Successfully connected on port $PORT"
        break
    fi
done

```

And it worked.
![](Pasted%20image%2020250226190041.png)

We got the port `3333`.
Lets connect.
And we are in.
![](Pasted%20image%2020250226190140.png)

Lets continue.
![](Pasted%20image%2020250226190237.png)
Hmm interesting.
![](Pasted%20image%2020250226190359.png)
And searching irb shell,we can see this.
![](Pasted%20image%2020250226190642.png)

Hmm So its a interactive ruby shell.
And we can get bash shell by this.
![](Pasted%20image%2020250226190721.png)
![](Pasted%20image%2020250226190739.png)

Lets continue.
And we got another flag.
![](Pasted%20image%2020250226190824.png)
`thm{sh3ll_3c4p3_15_v3ry_1337}`

Lets do a privelege escalation.
And we can see something interesting.
![](Pasted%20image%2020250226191002.png)

Lets go.
First we gonna tar archive the root directory.
`tar -cf /tmp/extracted.tar /root`

And then extract from that `extracted.tar` tar archive.
`tar -xf extracted.tar`

And we got `/root` directory.
![](Pasted%20image%2020250226191835.png)

Now we can directly read `root.txt`.
Or we can read `/etc/shadow`.
And we can see a user vagrant.
![](Pasted%20image%2020250226193105.png)

Root's password might be very hard to crack,So lets crack the hash of this user.
`hashcat -m 1800 -a 0 hash.txt /usr/share/wordlists/rockyou.txt`

And we got it.
`$6$XQAwkysB$wSkezwLStg6E8nT/h5ECcNdiBuGt98yNnjwVEB.YVEAQY9z5AamgBhYTUAzKRQjmNxpEOLP/a36mxdZyaKJk60:vagrant`

And it was just his/her name.
:)

![](Pasted%20image%2020250226193828.png)

Nice.
Lets login.
![](Pasted%20image%2020250226193908.png)
And doing `sudo -l` shows us we have a sudo permission to everything.
Lets became root.
`sudo su`

And my machine time also just finished after becoming root.
![](Pasted%20image%2020250226194056.png)

I will start new one.
![](Pasted%20image%2020250226194256.png)

And done.
![](Pasted%20image%2020250226194332.png)
