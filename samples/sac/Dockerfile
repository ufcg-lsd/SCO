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
# RUN sed -i 's/DEBUG/DEBUG_LEVEL/' ./restbed/source/corvusoft/restbed/logger.hpp
# RUN sed -i 's/DEBUG/DEBUG_LEVEL/' ./restbed/documentation/API.md
# RUN sed -i 's/DEBUG/DEBUG_LEVEL/' ./restbed/documentation/STANDARDS.md
# RUN sed -i 's/DEBUG/DEBUG_LEVEL/' ./restbed/example/syslog_logging/source/example.cpp
# RUN sed -i 's/DEBUG:/DEBUG_LEVEL:/' ./restbed/example/syslog_logging/source/syslog_logger.hpp
 RUN mkdir ./restbed/build
 WORKDIR /usr/src/restbed/build
 RUN cmake -DBUILD_TESTS=YES -DBUILD_EXAMPLES=YES -DBUILD_SSL=YES -DBUILD_SHARED=YES -DCMAKE_CXX_COMPILER=/usr/bin/g++-4.9 ..
 RUN make install
 ENV RESTBED_MODULES_PATH=/usr/src/restbed
 ENV LD_LIBRARY_PATH=/usr/src/restbed/distribution/library
 WORKDIR /usr/src
 RUN mkdir sac2017
 ADD ./sac2017 /usr/src/sac2017
 WORKDIR /usr/src/sac2017
 #RUN git checkout sac2017
 WORKDIR /usr/src
 RUN git clone https://github.com/edenhill/librdkafka.git
 WORKDIR /usr/src/librdkafka
 RUN ./configure
 RUN make
 RUN make install
 WORKDIR /usr/src/sac2017/Aggregator
 #TODO: MOVE INSTALATION OF KAFKA TO LINE 7
 ADD ./start.sh /usr/src/sac2017/Aggregator
 #RUN chmod 755 ./start.sh
 RUN cp -r /usr/src/restbed/build/librestbed.so.* /usr/local/lib
 RUN source /opt/intel/sgxsdk/environment
 RUN cp /home/sgx/drivers/restbed/distribution/library/librestbed.so.0 /usr/src/restbed/distribution/library
 RUN make SGX_MODE=HW SGX_DEBUG=1 
 RUN ldconfig
 RUN chmod 755 ./aggregator
EXPOSE 8888
RUN apt-get install curl
CMD /bin/bash -c "/opt/intel/sgxpsw/aesm/aesm_service &" && /bin/bash -c "sleep 15" && /bin/bash -c "source /opt/intel/sgxsdk/environment" && bash start.sh && /bin/bash -c "while true; do sleep 10; done"
#CMD /bin/bash -c "/opt/intel/sgxpsw/aesm/aesm_service &" && /bin/bash -c "sleep 15" && /bin/bash -c "source /opt/intel/sgxsdk/environment" && /bin/bash -c "while true; do sleep 10; done"
#CMD /bin/bash -c "ldconfig" && /bin/bash -c "chmod 755 ./aggregator" && /bin/bash -c "/opt/intel/sgxpsw/aesm/aesm_service &" && /bin/bash -c "source /opt/intel/sgxsdk/environment" && /bin/bash
# CMD /bin/bash -c "ls /dev/" && /bin/bash -c "ps aux | grep aesm" && /bin/bash -c "/opt/intel/sgxpsw/aesm/aesm_service &" && /bin/bash -c "sleep 15" && /bin/bash -c "echo Sleep time over"  && /bin/bash -c "source /opt/intel/sgxsdk/environment" && /bin/bash -c "while true; do sleep 10; done"


 #DEBUG FROM HERE
 #CMD /bin/bash
