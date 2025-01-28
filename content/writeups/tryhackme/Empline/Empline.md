# Empline 


## Enemuration

```
 rustscan -a 10.10.36.254
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where '404 Not Found' meets '200 OK'.

[~] The config file is expected to be at "/home/k21/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.36.254:80
Open 10.10.36.254:22
Open 10.10.36.254:3306
[~] Starting Script(s)
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-28 21:01 +0545
Initiating Ping Scan at 21:01
Scanning 10.10.36.254 [4 ports]
Completed Ping Scan at 21:01, 0.23s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:01
Completed Parallel DNS resolution of 1 host. at 21:01, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 21:01
Scanning 10.10.36.254 (10.10.36.254) [3 ports]
Discovered open port 80/tcp on 10.10.36.254
Discovered open port 3306/tcp on 10.10.36.254
Discovered open port 22/tcp on 10.10.36.254
Completed SYN Stealth Scan at 21:01, 0.21s elapsed (3 total ports)
Nmap scan report for 10.10.36.254 (10.10.36.254)
Host is up, received reset ttl 60 (0.20s latency).
Scanned at 2025-01-28 21:01:36 +0545 for 0s

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 60
80/tcp   open  http    syn-ack ttl 60
3306/tcp open  mysql   syn-ack ttl 60

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.64 seconds
           Raw packets sent: 7 (284B) | Rcvd: 4 (172B)


```

```
 nmap -sVC 10.10.36.254 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-28 21:00 +0545
Nmap scan report for 10.10.36.254 (10.10.36.254)
Host is up (0.24s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c0:d5:41:ee:a4:d0:83:0c:97:0d:75:cc:7b:10:7f:76 (RSA)
|   256 83:82:f9:69:19:7d:0d:5c:53:65:d5:54:f6:45:db:74 (ECDSA)
|_  256 4f:91:3e:8b:69:69:09:70:0e:82:26:28:5c:84:71:c9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Empline
|_http-server-header: Apache/2.4.29 (Ubuntu)
3306/tcp open  mysql   MySQL 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
|   Thread ID: 86
|   Capabilities flags: 63487
|   Some Capabilities: LongColumnFlag, InteractiveClient, Support41Auth, Speaks41ProtocolOld, LongPassword, DontAllowDatabaseTableColumn, SupportsTransactions, IgnoreSigpipes, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, ODBCClient, SupportsCompression, FoundRows, ConnectWithDatabase, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: 3C4{0z9JGhTNiFa6*mf<
|_  Auth Plugin Name: mysql_native_password
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.26 seconds

```


After that lets go to web page.
![](Pasted%20image%2020250128214705.png)
We can see there is `job` sub domain.
Lets manage it and go to that subdomain.
![](Pasted%20image%2020250128214802.png)

Hmm but before we have saw `/careers`.
Lets go there and see.
![](Pasted%20image%2020250128214854.png)

## Exploit

Hmm what is that `opencats`.
Lets search for it and its exploit.
And we can see this.
![](Pasted%20image%2020250128214946.png)

Lets go to exploit-db and try to exploit it.
I ran the exploit on `job.empline.thm` and it worked.
![](Pasted%20image%2020250128215111.png)

I also spend some time understanding the code and exploit.
So when we came here.
`http://job.empline.thm/careers/index.php?m=careers&p=applyToJob&ID=1`
there will be.
![](Pasted%20image%2020250128215239.png)

We can upload a file in that.
In my case, I uploaded a web shell and according to exploit and opencats, the file uploaded there will be saved in `http://job.empline.thm/upload/careerportaladd/` or `/upload/careerportaladd/` 

And we can put the files name and execute command like this.
`http://job.empline.thm/upload/careerportaladd/web.php?cmd=id`
![](Pasted%20image%2020250128215537.png)

Now we can easily get a rev shell by python3 rev shell.
![](Pasted%20image%2020250128215652.png)

## Privelege Escalation

Lets do further enemuration.
We can find `config.php` in `/var/www/opencats` directory.
And there is a password for DB of user james.
![](Pasted%20image%2020250128215902.png)
`ng6pUFvsGNtw`

Lets login and enemurate.
![](Pasted%20image%2020250128220206.png)
We got two password and one cracked so fast.
![](Pasted%20image%2020250128220234.png)
`pretonnevippasempre`

For now lets enemurate on cracked password and try to login with user `george`.
And we were successful.
![](Pasted%20image%2020250128220432.png)

Now lets try to escalate our privelege to the root.

After trying to find setuid and leaked password, I came to capabilities and got this.
![](Pasted%20image%2020250128221136.png)

Lets try to exploit it.

After doing some research and talking with chatGPT, I came up with this.
`/usr/local/bin/ruby -e 'File.chown(1002, 1002, "/etc/shadow")'`

It will change the owner of `/etc/shadow` file to our current user.
![](Pasted%20image%2020250128224536.png)

As our uid and gid is 1002, when we change the ownership of `/etc/shadow`  to 1002, It will make us the owner of `/etc/shadow` file.

After that we can just make its permission writable and change the root hash to george's hash as it will be easy as we also have a password for user george.
![](Pasted%20image%2020250128225009.png)

And we got the root.

