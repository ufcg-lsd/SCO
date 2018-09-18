FROM ubuntu:14.04
WORKDIR /home/sgx/app 
RUN git clone -b remote-attestation-sample https://amandasouza:jxg642d19nSw8z-Kfh-d@git.lsd.ufcg.edu.br/secure-cloud/sgx-apps.git remote-attestation-sample 
WORKDIR /home/sgx/app/remote-attestation-sample 
RUN SGX_MODE=HW SGX_DEBUG=1 RESTBED_PATH=/home/sgx/drivers/restbed make 
RUN echo "#/bin/bash" >> run.sh
RUN echo "/opt/intel/sgxpsw/aesm/aesm_service &" >> run.sh
RUN echo "sleep 1s" >> run.sh
RUN echo "cd /home/sgx/app/remote-attestation-sample/" >> run.sh
RUN echo "./app_final" >> run.sh
RUN chmod +x run.sh
RUN cp /opt/intel/sgxsdk/lib64/libsgx_urts_sim.so .
RUN cp /opt/intel/sgxsdk/lib64/libsgx_uae_service_sim.so .
#RUN source /opt/intel/sgxsdk/environment
CMD /bin/bash -c "while true; do sleep 100; done"
