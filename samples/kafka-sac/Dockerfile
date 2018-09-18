FROM ubuntu:14.04
MAINTAINER Gabriel Fernandez <gabrielpfernandez@gmail.com>
RUN apt-get update
RUN apt-get install -y git
RUN apt-get install -y software-properties-common build-essential cmake python
RUN apt-get install -y wget
RUN add-apt-repository ppa:ubuntu-toolchain-r/test 
RUN apt-get update
RUN apt-get install -y g++-4.9 git
RUN add-apt-repository ppa:webupd8team/java -y && \
    apt-get update && \
    echo oracle-java7-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections && \
    apt-get install -y oracle-java8-installer && \
    apt-get clean
WORKDIR /usr/src
RUN git clone https://github.com/edenhill/librdkafka.git
WORKDIR /usr/src/librdkafka
RUN ./configure
RUN make
RUN make install
RUN ldconfig
WORKDIR /usr/src
RUN wget http://ftp.unicamp.br/pub/apache/kafka/0.9.0.1/kafka_2.11-0.9.0.1.tgz
RUN tar xzf kafka_2.11-0.9.0.1.tgz
ENV KAFKA_PATH=/usr/src/kafka_2.11-0.9.0.1
EXPOSE 9092
ADD ./modify_hosts.sh /usr/src/modify_hosts.sh
RUN chmod +x /usr/src/modify_hosts.sh
RUN touch /usr/src/hosts
RUN cat /etc/hosts >> /usr/src/hosts
#Notice the kafka-sever-start.sh script must run after the 2181 part shows in netstat. If it is not, grep sign will be 1 and the loop will persist
#Shell form
CMD /bin/bash -c "cat /etc/hosts" && /bin/bash -c "/usr/src/modify_hosts.sh" && /usr/src/kafka_2.11-0.9.0.1/bin/zookeeper-server-start.sh -daemon /usr/src/kafka_2.11-0.9.0.1/config/zookeeper.properties && /bin/bash -c "sleep 5" && /bin/bash -c "cat /etc/hosts" && /usr/src/kafka_2.11-0.9.0.1/bin/kafka-server-start.sh /usr/src/kafka_2.11-0.9.0.1/config/server.properties && /bin/bash -c "while true; do sleep 10; done"
#CMD /usr/src/kafka_2.11-0.9.0.1/bin/zookeeper-server-start.sh usr/src/kafka_2.11-0.9.0.1/config/zookeeper.properties && /bin/bash -c "while true; do sleep 10; done"
#Exec form
#ENTRYPOINT ["/bin/bash", "-c", "sed -i '$d' /etc/hosts && /usr/src/kafka_2.11-0.9.0.1/bin/zookeeper-server-start.sh -daemon /usr/src/kafka_2.11-0.9.0.1/config/zookeeper.properties && sleep 5 && /usr/src/kafka_2.11-0.9.0.1/bin/kafka-server-start.sh -daemon /usr/src/kafka_2.11-0.9.0.1/config/server.properties && while true; do sleep 10; done"]
#CMD /bin/bash -c "while true; do sleep 10; done"
 
