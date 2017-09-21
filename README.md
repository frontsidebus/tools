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
