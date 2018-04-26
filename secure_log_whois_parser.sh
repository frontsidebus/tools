 #!/bin/bash
  2 #
  3 #
  4 INFILE=/root/failed_login_ips.txt
  5 #
  6 GETFAILS=/root/get_fails.sh
  7 #
  8 /bin/bash $GETFAILS
  9 #
 10 while read line
 11     do
 12         HOST="$(echo $line | awk '{print$2}')"
 13         REGEX='([A-Za-z]+\d*).*'
 14         OUTFILE=/root/resolved_hosts.txt
 15         if [[ $HOST =~ $REGEX ]]
 16                 then
 17                 #       echo "its a hostname"
 18                         echo $(echo $line | awk '{print$1}')" failed logins from "
 19                         echo $line | awk '{print$2}' >> $OUTFILE
 20                         dig $(echo $line | awk '{print$2}') | grep -A 1 -i answer | grep -i "IN A" | awk '{print$5}' >> $OUTFILE
 21                         tail -n 2 $OUTFILE
 22
 23                 else
 24                 #       echo "its an ip"
 25                         echo $(echo $line | awk '{print$1}')" failed logins from "
 26                         whois $(echo $line | awk '{print$2}') | grep -i netname
 27
 28                 fi
 29         sleep 1
 30     done < $INFILE
