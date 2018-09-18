#!/bin/bash

# Remove old SGX driver and SDK/PSW

if [ -d "/opt/intel/sgxpsw" ]; then
    service aesmd stop
    cd /opt/intel/sgxpsw
    ./uninstall.sh
    cd -
fi

if [ -d "/opt/intel/sgxsdk" ]; then
    cd /opt/intel/sgxsdk
    ./uninstall.sh
    cd -
fi

if [ -d "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx" ]; then
    /sbin/modprobe -r isgx
    rm -rf "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
    /sbin/depmod
    /bin/sed -i '/^isgx$/d' /etc/modules
fi

# Update

yes | apt-get update

# SGX dependencies

yes | apt-get install build-essential ocaml automake autoconf libtool wget python make libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev alien git uuid-dev libxml2-dev cmake pkg-config

# Git

yes | apt install git

# Python pip

yes | apt install python-pip

# ZMQ

yes | apt install libzmq3-dev
yes | pip install pyzmq

# Python cryptography

yes | pip install cryptography
yes | pip install pycrypto

# Python requests

yes | pip install requests

# Pwntools

yes | apt-get install python2.7 python-dev libssl-dev libffi-dev
yes | pip install --upgrade pwntools

## Trusted platform service

if [ ! \( -d "/opt/Intel/iclsClient" \) ]; then
    yes | wget http://registrationcenter-download.intel.com/akdlm/irc_nas/11414/iclsClient-1.45.449.12-1.x86_64.rpm
    yes | alien --scripts iclsClient-1.45.449.12-1.x86_64.rpm
    dpkg -i iclsclient_1.45.449.12-2_amd64.deb
    rm iclsClient-1.45.449.12-1.x86_64.rpm iclsclient_1.45.449.12-2_amd64.deb
fi
if [ ! \( -d "/etc/jhi" \) ]; then
    git clone https://github.com/intel/dynamic-application-loader-host-interface.git
    cd dynamic-application-loader-host-interface
    cmake .;make;make install;systemctl enable jhi
    cd ..
    rm -rf dynamic-application-loader-host-interface
fi

# SGX driver

git clone https://github.com/01org/linux-sgx-driver.git
cd linux-sgx-driver
git checkout sgx_driver_1.9
make
mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"
/sbin/depmod
/sbin/modprobe isgx
cd ..
rm -rf linux-sgx-driver

# SGX SDK and PSW

git clone https://github.com/01org/linux-sgx.git
cd linux-sgx
git checkout sgx_1.9
cp ../63.patch .

git apply 63.patch

yes | ./download_prebuilt.sh
make
make sdk_install_pkg
make psw_install_pkg
cd linux/installer/bin/
python -c "print 'no\n/opt/intel'" | ./sgx_linux_x64_sdk_*.bin
./sgx_linux_x64_psw*.bin
cd ../../../../
rm -rf linux-sgx
