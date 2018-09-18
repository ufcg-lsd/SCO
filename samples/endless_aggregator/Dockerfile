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
RUN git clone https://github.com/edenhill/librdkafka.git
WORKDIR /usr/src/librdkafka
RUN ./configure
RUN make
RUN make install
ADD app /usr/src/app
WORKDIR /usr/src/app/Aggregator
 RUN apt-get install -y curl
 RUN apt-get install -y vim
#TODO: MOVE INSTALATION OF KAFKA TO LINE 7
 RUN cp -r /usr/src/restbed/build/librestbed.so.* /usr/local/lib
 RUN source /opt/intel/sgxsdk/environment
 RUN cp /home/sgx/drivers/restbed/distribution/library/librestbed.so.0 /usr/src/restbed/distribution/library
 RUN echo "/opt/intel/sgxsdk/lib64/" > /etc/ld.so.conf.d/sgx.conf
 RUN ldconfig
 RUN make 
 RUN chmod 755 ./aggregator
 EXPOSE 8888
 ADD ./start.sh /usr/src/app/Aggregator
 #THE /etc/hosts line addition is ad hoc to run in a certain environment.
 CMD /bin/bash -c "/opt/intel/sgxpsw/aesm/aesm_service &" && /bin/bash -c "sleep 15" && /bin/bash -c "echo '10.5.0.15 manager-sco-exp' >> /etc/hosts && cat /etc/hosts && source /opt/intel/sgxsdk/environment && bash start.sh" && /bin/bash -c "while true; do sleep 10; done'"
  #DEBUG FROM HERE
   #CMD /bin/bash


