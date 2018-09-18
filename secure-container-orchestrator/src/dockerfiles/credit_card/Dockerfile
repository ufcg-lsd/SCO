FROM ubuntu:14.04
 MAINTAINER Gabriel Fernandez <gabrielpfernandez@gmail.com>
 RUN apt-get update
 RUN apt-get install -y python-pip python-dev build-essential
 COPY . /app
 WORKDIR /app
 RUN pip install Flask
 EXPOSE 5000
 CMD python app.py
 
 

# The following code installs sgxs drivers and was automatically generated

#RUN apt-get update && apt-get install -y openssh-server build-essential linux-headers-3.19.0-30-generic curl git libcurl4-openssl-dev protobuf-compiler protobuf-c-compiler libprotobuf-dev libprotobuf-c0-dev ocaml automake autoconf libtool
#RUN git clone https://github.com/01org/linux-sgx-driver.git
#WORKDIR /linux-sgx-driver
#RUN make
#RUN mkdir -p "/lib/modules/3.19.0-30-generic/kernel/drivers/intel/sgx"
#RUN cp isgx.ko "/lib/modules/3.19.0-30-generic/kernel/drivers/intel/sgx"
#RUN sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"
#RUN /sbin/depmod
#RUN /sbin/modprobe isgx
#WORKDIR /
#RUN git clone https://github.com/01org/linux-sgx.git
#RUN cd linux-sgx && ./download_prebuilt.sh
#RUN cd linux-sgx && make
#RUN cd linux-sgx && make sdk_install_pkg
#RUN cd linux-sgx && make psw_install_pkg
#WORKDIR linux-sgx/linux/installer/bin/
#RUN yes | ./sgx_linux_x64_sdk_1.6.100.34922.bin
#RUN yes | ./sgx_linux_x64_psw_1.6.100.34922.bin
#RUN mkdir /var/run/sshd
#RUN echo 'root:securecloud' | chpasswd
#RUN sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config
# SSH login fix. Otherwise user is kicked off after login
#RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
#ENV NOTVISIBLE "in users profile"
#RUN echo "export VISIBLE=now" >> /etc/profile

# Auto generated code ends here

