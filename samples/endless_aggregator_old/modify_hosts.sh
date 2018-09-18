#!/bin/bash
cp /etc/hosts ~/hosts.new
sed -i '1i172.17.0.1 manager-sco-exp' ~/hosts.new
echo "$(cat ~/hosts.new)" > /etc/hosts

