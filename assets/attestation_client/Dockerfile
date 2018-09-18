FROM docker-sgx

ARG SERVER_IP

RUN apt-get update && apt-get -y install libzmq3-dev libcrypto++-dev libboost-dev libboost-chrono-dev libboost-system-dev && rm -rf /var/lib/apt/lists/*

#Simple Remote Attestation2 App 
WORKDIR /home/sgx/app 
RUN git clone -b remote-attestation3-SCO https://amandasouza:jxg642d19nSw8z-Kfh-d@git.lsd.ufcg.edu.br/secure-cloud/sgx-apps.git remote-attestation3-SCO
WORKDIR /home/sgx/app/remote-attestation3-SCO/Client
RUN make 
RUN echo "#!/bin/bash" >> run.sh  
RUN echo "cd /home/sgx/app/remote-attestation3-SCO/Client" >> run.sh
RUN echo "./client $SERVER_IP:8888" >> run.sh
RUN chmod +x run.sh 

CMD ["/home/sgx/app/remote-attestation3-SCO/Client/run.sh"]
