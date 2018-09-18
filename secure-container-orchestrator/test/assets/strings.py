remote_attestation_build_response = 'FROM docker-sgx\n\nRUN apt-get update && apt-get -y install libzmq3-dev libcrypto++-dev libboost-dev libboost-chrono-dev libboost-system-dev && rm -rf /var/lib/apt/lists/*\n\n#Simple Remote Attestation2 App \nWORKDIR /home/sgx/app \nRUN git clone -b remote-attestation3-SCO https://amandasouza:jxg642d19nSw8z-Kfh-d@git.lsd.ufcg.edu.br/secure-cloud/sgx-apps.git remote-attestation3-SCO \nWORKDIR /home/sgx/app/remote-attestation3-SCO/SP \nRUN make SGX_MODE=HW SGX_DEBUG=1 \nRUN echo "#!/bin/bash" >> run.sh \nRUN echo "/opt/intel/sgxpsw/aesm/aesm_service &" >> run.sh \nRUN echo "sleep 1s" >> run.sh \nRUN echo "cd /home/sgx/app/remote-attestation3-SCO/SP" >> run.sh\nRUN echo "./service_provider" >> run.sh\nRUN chmod +x run.sh \nEXPOSE 8888\nCMD while true; do /bin/bash /home/sgx/app/remote-attestation3-SCO/SP/run.sh; done;\n#CMD /bin/bash -c "while true; do sleep 10; done"'
duplicate_id_error = '[ERROR] The chosen id is already taken. Please, chose another one. Operation aborted'
invalid_dockerfile_error = '[ERROR] Build was unsuccesful. Invalid Dockerfile'
too_many_instances_error = '[ERROR] The instances amount value exceeds the limit per cluster. Try a lower value'

def get_dockerfile_from_response(response):
    try:
        begin = response.index("FROM")
    except ValueError:
        return response
    no_header = response[begin:]
    end = no_header.index("\nPK")
    return no_header[:end]

    
    
        

