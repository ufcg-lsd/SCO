#!/bin/bash

function usage
{
    echo "usage: sudo ./sgx-install [-x]"
}

executable_heap='false'
# Program options
while [ "$1" != "" ]; do
    case $1 in
        -xh )   executable_heap='true' ;;
        *   )   usage
                exit 1
    esac
    shift
done

# SGX dependencies
yes | apt-get install build-essential ocaml automake autoconf libtool wget python make libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev alien git uuid-dev libxml2-dev cmake pkg-config

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

# SGX SDK and PSW

git clone https://github.com/01org/linux-sgx.git
cd linux-sgx
git checkout 2ef16f684ed040f06eafc09fa41c264a16296d41

# Optional executable heap

if [ $executable_heap == 'true' ]; then
    echo "Executable heap: true" > ../xh
    # cp ../executable_heap.patch .
    cp ../63.patch .
    # git apply executable_heap.patch
    git apply 63.patch
else
    echo "Executable heap: false" > ../xh
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
