FROM aminueza/docker-sgx

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends apt-utils
RUN apt-get update && apt-get install -y linux-headers-`uname -r` kmod
RUN apt-get install -y --reinstall linux-image-`uname -r`
RUN apt-get install -y git gcc

ADD ./install_dependencies.sh .
RUN chmod 777 install_dependencies.sh
RUN ./install_dependencies.sh


#ADD ./install_latest_sgx_driver.sh .
ADD ./install_latest_sgx_psw_sdk.sh .
RUN chmod 777 install_latest_sgx_psw_sdk.sh
ADD ./63.patch .
RUN chmod 666 63.patch

#RUN ./install_latest_sgx_driver.sh
RUN chmod 777 install_latest_sgx_psw_sdk.sh
RUN ./install_latest_sgx_psw_sdk.sh -xh

ADD ./DynSGX ./DynSGX
RUN chmod 777 ./DynSGX/server/DynSGX

#ADD ./enclave.signed.so .

RUN apt-get update && apt-get install -y libzmq-dev

ENV DEBIAN_FRONTEND teletype

CMD /bin/bash -c "source /opt/intel/sgxsdk/environment && ./opt/intel/sgxpsw/aesm/aesm_service &" && /bin/bash -c "sleep 4 && cd /DynSGX/server && ./DynSGX &" && /bin/bash -c "while true; do sleep 10; done"
