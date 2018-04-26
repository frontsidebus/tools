#!/bin/bash
#grep "failure;" /var/log/secure | awk -F "=" '{print$7}' | awk '{print$1}' | sort | uniq -c | sort -rn > failed_login_ips.txt
#
AUTHLOGS=/var/log/secure
OUTFILE=/root/failed_login_ips.txt
#
get_failed_auths () {
        grep "failure;" $AUTHLOGS | awk -F "=" '{print$7}' | awk '{print$1}' | sort | uniq -c | sort -rn > $OUTFILE
}
get_failed_auths
