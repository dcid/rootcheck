#!/bin/sh
# Wrapper for rootcheck.
# 1- It will call ossec-rootcheck.
# 2- It will run a basic forensic analysis on the logs showing all last logins
# 
# Author: Daniel B. Cid <daniel.cid@gmail.com>
# Last modification: Feb 10, 2016


### 1- We start by running ossec-rootcheck
./ossec-rootcheck


### 2- We try to find the log files to parse:
listoflogs="/var/log/secure /var/log/secure.1 /var/log/auth.log /var/log/auth.log.1"
logfound=""
for i in $listoflogs; do
    ls -la $i >/dev/null 2>&1
    if [ $? = 0 ]; then
        logfound="$logfound $i"    
    fi
done

if [ ! "x$logfound" = "x" ]; then
    echo "[INFO]: Latest successful logins to the server:"
    cat $logfound | ./src/analysisd/ossec-logtest -a 2>&1 |./src/monitord/ossec-reportd -p -f group authentication_succ -r user srcip 2>&1 |grep -A 1000 "Related entries for 'Username'" |grep -v "Related entries for 'Username'" |grep -v -- "------------------------------------------------"
fi
