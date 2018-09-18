#!/bin/bash
cp /etc/hosts ~/hosts.mod
host_name=$(awk 'END {print $NF}' ~/hosts.mod)
host_ip=$(awk 'END {print $1}' ~/hosts.mod)
sed -i "s|$host_name|$host_ip|" ~/hosts.mod
cp -f ~/hosts.mod /etc/hosts
echo $host_name > ~/hostname
cp -f ~/hostname /etc/hostname
cat /etc/hostname

