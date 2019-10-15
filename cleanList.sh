#! /bin/sh

dos2unix $1
vim -c "set encoding=utf8" -c "set fileencoding=utf8" -c "wq" $1

sed -i /"^255.255.255.255 broadcasthost"/d $1
sed -i /"^127.0.0.1 local"/d $1

sed -i s/"^#0\.0\.0\.0\s+"//g $1
sed -i s/"^#127\.0\.0\.1\s+"//g $1

sed -i s/"^#0.0.0.0 +"//g $1
sed -i s/"^#127.0.0.1 +"//g $1

sed -i s/"^0\.0\.0\.0\s+"//g $1
sed -i s/"^127\.0\.0\.1\s+"//g $1

sed -i s/"^0.0.0.0 "//g $1
sed -i s/"^127.0.0.1 "//g $1
sed -i s/"^127.0.0.1	"//g $1
sed -i s/"^255.255.255.255 "//g $1
sed -i s/"(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))(\n|\r|$| |	| +|	+)"//g $1
sed -i s/"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\n|\r|$| |	| +|	+)"//g $1

sed -i s/"Malvertising list by Disconnect"//g $1

sed -i s/^#.*//g $1
sed -i s/" #.*"//g $1
sed -i s/" "//g $1

sed -i /"localhost"/d $1
sed -i /"^$"/d $1
