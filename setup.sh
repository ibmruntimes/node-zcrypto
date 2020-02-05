#!/usr/bin/env bash

USERID=$(whoami)
HOSTNAME=$(hostname | sed -e "s/\.torolab\.ibm\.com//")
RANDFILE=''; for i in {0..31}; do RANDFILE+=$(printf "%x" $(($RANDOM%16)) ); done;

cp cert.jcl /tmp/cert.$USERID.$HOSTNAME.$RANDFILE.jcl
perl -pi -e "s/USERID/$USERID/g" /tmp/cert.$USERID.$HOSTNAME.$RANDFILE.jcl
perl -pi -e "s/HOSTNAME/$HOSTNAME/g" /tmp/cert.$USERID.$HOSTNAME.$RANDFILE.jcl
zsubmit.pl /tmp/cert.$USERID.$HOSTNAME.$RANDFILE.jcl || true
