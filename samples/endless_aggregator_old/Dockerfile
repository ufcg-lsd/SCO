FROM aminueza/docker-sgx
 MAINTAINER gabrielpfernandez <gabrielpfernandez@gmail.com>
 WORKDIR /usr/src
 ADD ./install_sgx_latest.sh ./
 ADD ./63.patch ./
 RUN chmod 755 ./install_sgx_latest.sh
 RUN chmod 755 ./63.patch
 RUN ./install_sgx_latest.sh
 RUN rm /bin/sh && ln -s /bin/bash /bin/sh
 RUN add-apt-repository ppa:ubuntu-toolchain-r/test
 RUN apt-get update
 RUN apt-get install -y g++-5 g++-4.9 git
 RUN add-apt-repository -r ppa:ubuntu-toolchain-r/test
 RUN git clone --recursive https://git.lsd.ufcg.edu.br/restbed/restbed.git
 RUN mkdir ./restbed/build
 WORKDIR /usr/src/restbed/build
 RUN cmake -DBUILD_EXAMPLES=YES -DBUILD_SSL=YES -DBUILD_SHARED=YES -DCMAKE_CXX_COMPILER=/usr/bin/g++-4.9 ..
 RUN make install
 ENV RESTBED_MODULES_PATH=/usr/src/restbed
 ENV LD_LIBRARY_PATH=/usr/src/restbed/distribution/library
 WORKDIR /usr/src
 RUN mkdir app
 ADD ./app /usr/src/app
 WORKDIR /usr/src/app
 #RUN git checkout sac2017
 WORKDIR /usr/src
 RUN git clone https://github.com/edenhill/librdkafka.git
 WORKDIR /usr/src/librdkafka
 RUN ./configure
 RUN make
 RUN make install
 WORKDIR /usr/src/app/Aggregator
 RUN cp -r /usr/src/restbed/build/librestbed.so.* /usr/local/lib
 RUN source /opt/intel/sgxsdk/environment
 RUN cp /home/sgx/drivers/restbed/distribution/library/librestbed.so.0 /usr/src/restbed/distribution/library
 RUN make SGX_MODE=HW SGX_DEBUG=1 
 RUN ldconfig
 RUN chmod 755 ./aggregator
 CMD /bin/bash -c "/opt/intel/sgxpsw/aesm/aesm_service &" && /bin/bash -c "sleep 13"  && /bin/bash -c "source /opt/intel/sgxsdk/environment" /bin/bash -c "echo '10.5.0.15 manager-sco-exp' >> /etc/hosts" && /bin/bash -c "./aggregator 10.5.0.15:9092 region_test 600"

