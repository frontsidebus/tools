# Linux and Windows Scripts and One-liners
# 
Anything overtly dangerous, I have tried to comment as such. Most of the other things included here are read only commands or scripts that could be useful depending on the situation 


**Stingray VTM Log TLS Version (TS)**
```py
#Example script, that sends the string to log.info:
#Get the encryption cipher
$cipher = ssl.clientCipher(); 
log.info( "Encrypted with ".$cipher );
```

**Python script for debugging TLS connections, specifically "client-hello"**
```
#!/usr/bin/env python
# Hack-and-slash derived from https://github.com/pquerna/tls-client-hello-stats

import os, sys, dpkt
TLS_HANDSHAKE = 22

def pcap_reader(fp):
    return dpkt.pcap.Reader(fp)

def grab_negotiated_ciphers(cap):
    for ts, buf in cap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        tcp = ip.data
        if (tcp.dport != 443 and tcp.sport != 443) or (len(tcp.data) <= 0) or (ord(tcp.data[0]) != TLS_HANDSHAKE):
            continue

        records = []
        try:
            records, bytes_used = dpkt.ssl.TLSMultiFactory(tcp.data)
        except dpkt.ssl.SSL3Exception, e:
            continue
        except dpkt.dpkt.NeedData, e:
            continue

        if len(records) <= 0:
            continue

        for record in records:
            # TLS handshake only
            if (record.type == 22 and len(record.data) != 0 and ord(record.data[0]) == 2):
                try:
                    handshake = dpkt.ssl.TLSHandshake(record.data)
                except dpkt.dpkt.NeedData, e:
                    continue
                if isinstance(handshake.data, dpkt.ssl.TLSServerHello):
                    ch = handshake.data
                    print '%s\t0x%0.2x,0x%0.2x' %(dpkt.ssl.ssl3_versions_str[ch.version], (ch.cipher_suite&0xff00)>>8, ch.cipher_suite&0xff)
                else:
                    continue

def main(argv):
    if len(argv) != 2:
        print "Tool to grab and print TLS Server Hello cipher_suite"
        print ""
        print "Usage: parser.py <pcap file>"
        print ""
        sys.exit(1)

    with open(argv[1], 'rb') as fp:
        capture = pcap_reader(fp)
        stats = grab_negotiated_ciphers(capture)

if __name__ == "__main__":
    main(sys.argv)
```

**Linux Disk Usage Analysis**
```sh
#!/bin/bash
#
#Run this inside the parent directory, it will read recursively...
#
FS='./';resize;clear;date;df -h $FS; echo "Largest Directories:"
#so we don't bury the machine running these read heavy commands
nice -n19 find $FS -mount -type d -print0 2>/dev/null|xargs -0 du -k|sort -runk1|head -n20|awk '{printf "%8d MB\t%s\n",($1/1024),$NF}'
#output to standard out
echo "Largest Files:"
#probably a better way to do this, but again we nice it so we don't bury the machine in io
nice -n 19 find $FS -mount -type f -print0 2>/dev/null| xargs -0 du -k | sort -rnk1| head -n20 |awk '{printf "%8d MB\t%s\n",($1/1024),$NF}'
```
*above as one-liner*
```sh
FS='./';resize;clear;date;df -h $FS; echo "Largest Directories:"; nice -n19 find $FS -mount -type d -print0 2>/dev/null|xargs -0 du -k|sort -runk1|head -n20|awk '{printf "%8d MB\t%s\n",($1/1024),$NF}';echo "Largest Files:"; nice -n 19 find $FS -mount -type f -print0 2>/dev/null| xargs -0 du -k | sort -rnk1| head -n20 |awk '{printf "%8d MB\t%s\n",($1/1024),$NF}';
```

***Windows dump failover configuration***
```
# Ugly script that gathers cluster info for 
# Failover Cluster manager in Server 2012
# Failover ip's and the network configuration are both dropped into a backup file
# Cluster configuration is dropped into a separate file
#
# This probably should have been done better...
#
#
ipconfig /all | Out-File C:\Users\administrator\Downloads\ipconfig_pre.txt
Get-ClusterResource | where {$_.resourcetype -eq "IP Address"} | format-list | Out-File C:\Users\administrator\Downloads\ipconfig_pre.txt -Append
Import-Module -Name FailoverClusters
Get-Cluster | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt
Get-ClusterAccess | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterNode | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterQuorum | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterGroup | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterResource | Sort-Object -Property OwnerGroup, Name | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterResource | Sort-Object -Property OwnerGroup, Name | Get-ClusterResourceDependency | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterResource | Get-ClusterOwnerNode | Where-Object -FilterScript { $_.OwnerNodes.Count -ne ( Get-ClusterNode ).Count } | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
```
***Linux LVM - translate Volume Group to scsi channel***
```sh
echo "connected disks" > /root/disks.txt; echo "physical volumes" > /root/physical_volumes.txt; ls -ld /sys/block/sd*/device | awk '{print$9}' | cut -d \/ -f 4 >> /root/disks.txt; pvs | awk '{print$1}' | cut -d \/ -f 3 | sort >> /root/physical_volumes.txt; diff -y /root/disks.txt /root/physical_volumes.txt
```
*alternate formatted version, thanks to Jeff V.*
```sh
echo -en 'DISK\t\tVG\n-----\t\t--\n' ; for i in /sys/block/sd*/device; do echo -n $(ls -ld $i | cut -d'/' -f 4,8 | sed 's/\// /gi') ; echo -ne '\t' ; pvs | tail -n +2 | grep $(echo $i | cut -d'/' -f4) | awk '{print $2}' ; echo ; done
```
*output should look like:*
```
#   DISK            VG
#   -----           --
#   sda 2:0:0:0
#   sdb 2:0:1:0     os
```
***Windows Enable UAC***
```
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -Value 1 
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system -Name ConsentPromptBehaviorAdmin -Value 4
```
***Linux - mysql - list sizes of all databases in instance***
*this is a read HEAVY query and should only be run off-production hours*
```
mysql>SELECT table_schema AS "Database name", SUM(data_length + index_length) / 1024 / 1024 AS "Size (MB)" FROM information_schema.TABLES GROUP BY table_schema;
```
*use this to list count by name w/o getting sizes*
```
SELECT count(*) FROM information_schema.SCHEMATA WHERE schema_name NOT IN ('mysql','information_schema');
```
***Linux - nmap - list supported ciphers on endpoint***
*BE CAREFUL WITH NMAP, BECAUSE IF YOU DON'T KNOW WHAT YOU ARE DOING, YOU CAN VERY EASILY START TRIGGERING ALARMS BY SCANNING HOSTS WITH RECKLESS ABANDON.*
*THE BELOW IS SAFE BECAUSE YOU ARE EXPLICITY DEFINING THE PORT, SO THE CONNECTION IS EFFECTIVELY THE SAME AS THE TLS HANDSHAKE THAT TAKES PLACE DURING AT THE BEGINNING OF ANY HTTPS CONNECTION.*
*DO NOT JUST RUN NMAP AGAINST A HOST IN OUR NETWORK WITHOUT ANY FLAGS. AT BEST SOC WILL COME TELL YOU TO STOP.*
*the below uses nmap to "scan" for supported ciphers on a specific host, using a specific port (in this case 443)*
```sh
nmap --script ssl-enum-ciphers -p 443 <ip address>
```
***Powershell Get OS info***
```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```
***Powershell Promote to Domain Controller***
```
#
# Windows PowerShell script for AD DS Deployment
#
Import-Module ADDSDeployment
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "Win2012R2" `
-DomainName "rogue-2.local" `
-DomainNetbiosName "ROGUE-2" `
-ForestMode "Win2012R2" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true
```
***Linux Hot CPU add (system doesn't recognize hot added CPU's)***
*check for any CPU's listed as "NO" for "online"*
```sh
lscpu -a --extended
```
*output should give you something like:*
```
[root@LAB01-01 ~]# lscpu -a --extended
CPU NODE SOCKET CORE L1d:L1i:L2:L3 ONLINE
0 0 0 0 0:0:0:0 yes
1 0 1 1 1:1:1:1 yes
2 - - - ::: no
3 - - - ::: no
```
*then use the below to online the CPU(s)*
```sh
echo 1 > /sys/devices/system/cpu/cpu2/online
```
***Linux Debugging website response times***
*stolen from https://gist.github.com/manifestinteractive/ce8dec10dcb4725b8513*
```
\n
=============  HOST:  ==========\n
\n
           local_ip:  %{local_ip}\n
         local_port:  %{local_port}\n
          remote_ip:  %{remote_ip}\n
        remote_port:  %{remote_port}\n
\n
=======  CONNECTION:  ==========\n
\n
       http_version:  %{http_version}\n
          http_code:  %{http_code}\n
       http_connect:  %{http_connect}\n
       num_connects:  %{num_connects}\n
      num_redirects:  %{num_redirects}\n
       redirect_url:  %{redirect_url}\n
\n
=============  FILE:  ==========\n
\n
       content_type:  %{content_type}\n
 filename_effective:  %{filename_effective}\n
     ftp_entry_path:  %{ftp_entry_path}\n
      size_download:  %{size_download}\n
        size_header:  %{size_header}\n
       size_request:  %{size_request}\n
        size_upload:  %{size_upload}\n
     speed_download:  %{speed_download}\n
       speed_upload:  %{speed_upload}\n
  ssl_verify_result:  %{ssl_verify_result}\n
      url_effective:  %{url_effective}\n
\n
===  TIME BREAKDOWN:  ==========\n
\n
    time_appconnect:  %{time_appconnect}\n
       time_connect:  %{time_connect}\n
    time_namelookup:  %{time_namelookup}\n
   time_pretransfer:  %{time_pretransfer}\n
      time_redirect:  %{time_redirect}\n
 time_starttransfer:  %{time_starttransfer}\n
                      ----------\n
         time_total:  %{time_total}\n
\n
```
*stick the above somewhere it can be referenced later*
```sh
#drop this in your .bash_profile
alias sniff='curl -w "@/Users/pbryant/sniff.txt" -o /dev/null -s'
```
*example output:*
```sh
C02JD2ZDDKQ5:~ pbryant$ sniff google.com

=============  HOST:  ==========

           local_ip:  127.0.0.1
         local_port:  53409
          remote_ip:  172.217.9.174
        remote_port:  80

=======  CONNECTION:  ==========

curl: unknown --write-out variable: 'http_version'
       http_version:  
          http_code:  301
       http_connect:  000
       num_connects:  1
      num_redirects:  0
       redirect_url:  http://www.google.com/

=============  FILE:  ==========

       content_type:  text/html; charset=UTF-8
 filename_effective:  /dev/null
     ftp_entry_path:  
      size_download:  219
        size_header:  321
       size_request:  74
        size_upload:  0
     speed_download:  2853.000
       speed_upload:  0.000
  ssl_verify_result:  0
      url_effective:  HTTP://google.com/

===  TIME BREAKDOWN:  ==========

    time_appconnect:  0.000
       time_connect:  0.015
    time_namelookup:  0.014
   time_pretransfer:  0.015
      time_redirect:  0.000
 time_starttransfer:  0.077
                      ----------
         time_total:  0.077

C02JD2ZDDKQ5:~ pbryant$ 
```

***check if sysVinit service is running using exit code, then performance a conditional action***
```sh
if [[ -z $(/etc/init.d/MyService status) ]]; then echo "MyService is down "; else echo "MyService is up "; fi;
```
