FROM ubuntu:14.04
MAINTAINER Gabriel Fernandez <gabrielpfernandez@gmail.com>

RUN apt-get update
RUN apt-get install -y libzmq3-dev libcrypto++-dev libboost-dev libboost-chrono-dev libboost-system-dev
RUN mkdir remote-attestation3-SCO 
ADD remote-attestation3-SCO /remote-attestation3-SCO
WORKDIR /remote-attestation3-SCO/Client
CMD ./client 
 

