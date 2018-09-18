#!/bin/bash
cp /etc/hosts ~/changeable_hosts
sed -i '/$^\ /s/*/\ ' ~/changeable_hosts
cp -f ~/changeable_hosts /etc/hosts
