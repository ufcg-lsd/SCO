#!/bin/bash

function usage
{
    echo "usage: sudo ./install_latest_sgx_driver.sh"
}

# Dependencies
yes | apt-get install git python make

# SGX driver
git clone https://github.com/01org/linux-sgx-driver.git
cd linux-sgx-driver
git checkout 78fec634b88078061b52cbbff38b6f6d3303af2e

make
mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"
/sbin/depmod
/sbin/modprobe isgx
cd ..
rm -rf linux-sgx-driver
