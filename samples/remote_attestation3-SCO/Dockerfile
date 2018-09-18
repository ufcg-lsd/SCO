FROM aminueza/docker-sgx

RUN apt-get update && apt-get -y install libzmq3-dev libcrypto++-dev libboost-dev libboost-chrono-dev libboost-system-dev && rm -rf /var/lib/apt/lists/*

#Simple Remote Attestation2 App 
WORKDIR /home/sgx/app 
RUN git clone -b remote-attestation3-SCO https://amandasouza:jxg642d19nSw8z-Kfh-d@git.lsd.ufcg.edu.br/secure-cloud/sgx-apps.git remote-attestation3-SCO 
WORKDIR /home/sgx/app/remote-attestation3-SCO/SP 
RUN make SGX_MODE=HW SGX_DEBUG=1 
RUN echo "#!/bin/bash" >> run.sh 
RUN echo "/opt/intel/sgxpsw/aesm/aesm_service &" >> run.sh 
RUN echo "sleep 1s" >> run.sh 
RUN echo "cd /home/sgx/app/remote-attestation3-SCO/SP" >> run.sh
RUN echo "./service_provider" >> run.sh
RUN chmod +x run.sh 
EXPOSE 8888
CMD while true; do /bin/bash /home/sgx/app/remote-attestation3-SCO/SP/run.sh; done;
#CMD /bin/bash -c "while true; do sleep 10; done"
