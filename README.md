# Linux and Windows Scripts and One-liners
# 
Anything overtly dangerous, I have tried to comment as such. Most of the other things included here are read only commands or scripts that could be useful depending on the situation 


*Stingray VTM Log TLS Version (TS)*
```py
#Example script, that sends the string to log.info:
#Get the encryption cipher
$cipher = ssl.clientCipher(); 
log.info( "Encrypted with ".$cipher );
```

*Python script for debugging TLS connections, specifically "client-hello"*
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
