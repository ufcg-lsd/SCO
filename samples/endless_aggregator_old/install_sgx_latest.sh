#!/bin/bash

function usage
{
    echo "usage: sudo ./sgx-install [-xh]"
}

executable_heap=false

while [ "$1" != "" ]; do
    case $1 in
        -xh )   executable_heap=true
                ;;
        * )     usage
                exit 1
    esac
    shift
done

# Remove old SGX driver and SDK/PSW

if [ -d "/opt/intel/sgxpsw" ]; then
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

# Git

apt install -y git

# Python

apt install -y python

# SGX dependencies

apt install -y build-essential ocaml automake autoconf libtool wget python make
apt install -y libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev

# SGX driver

git clone https://github.com/01org/linux-sgx-driver.git
cd linux-sgx-driver
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

# Optional executable heap

if [ executable_heap ]; then
    cp ../63.patch .
    git apply 63.patch
fi

yes | ./download_prebuilt.sh
make
make sdk_install_pkg
make psw_install_pkg
cd linux/installer/bin/
python -c "print 'no\n/opt/intel'" | ./sgx_linux_x64_sdk_*.bin
./sgx_linux_x64_psw*.bin
cd ../../../../
rm -rf linux-sgx
