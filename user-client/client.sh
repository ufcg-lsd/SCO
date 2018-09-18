#!/bin/bash
apt-get update
apt-get install -y libzmq3-dev libcrypto++-dev libboost-dev libboost-chrono-dev
./client $1
 

