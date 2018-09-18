FROM ubuntu
MAINTAINER gabrielf@lsd.ufcg.edu.br
RUN apt-get update && apt-get install -y curl
ADD ./SmartMeter /usr/src/SmartMeter
WORKDIR /usr/src/SmartMeter
ADD ./install_sgx_latest.sh /usr/src/SmartMeter
RUN ./install_sgx_latest.sh
#install general c dependencies
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:ubuntu-toolchain-r/test
RUN apt-get update
RUN apt-get install -y g++-5 g++-4.9 git
#install restbed REST client
RUN add-apt-repository -r ppa:ubuntu-toolchain-r/test
RUN git clone --recursive https://git.lsd.ufcg.edu.br/restbed/restbed.git
RUN apt-get install -y cmake
RUN mkdir ./restbed/build
WORKDIR /usr/src/SmartMeter/restbed/build
RUN cmake -DBUILD_TESTS=YES -DBUILD_EXAMPLES=YES -DBUILD_SSL=YES -DBUILD_SHARED=YES -DCMAKE_CXX_COMPILER=/usr/bin/g++-4.9 ..
RUN make install
ENV RESTBED_MODULES_PATH=/usr/src/SmartMeter/restbed
ENV LD_LIBRARY_PATH=/usr/src/SmartMeter/restbed/distribution/library
#install librdkafka for communication with kafka pub/sub
WORKDIR /usr/src/SmartMeter
RUN git clone https://github.com/edenhill/librdkafka.git
WORKDIR /usr/src/SmartMeter/librdkafka
RUN ./configure
RUN make
RUN make install
#run smartmeter application
WORKDIR /usr/src/SmartMeter/
RUN make
#RUN make install
CMD /bin/bash -c "source /opt/intel/sgxsdk/environment && ldconfig && ./smart-meter 10.30.0.20:9092 region_malvinas 3 100 1 10.30.0.20 8082 &" && /bin/bash -c "while true; do sleep 10; done"
