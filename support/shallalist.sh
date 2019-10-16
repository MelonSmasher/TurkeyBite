#!/usr/bin/env bash

# Downloads domain lists from shallalist.de
# run this only once per day
# Hosts them locally so we aren't blocked for excessive downloads

URL="http://www.shallalist.de/Downloads/shallalist.tar.gz"
FILE="/tmp/shallalist.tar.gz"
WEB_DIR="/usr/share/nginx/html/res/files/shallalist"

curl -o $FILE $URL
rm -rf $WEB_DIR
mkdir $WEB_DIR
tar -zxvf $FILE -C $WEB_DIR
chown -R nginx:nginx /usr/share/nginx/html/res/files/shallalist/
rm $FILE
