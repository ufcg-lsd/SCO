FROM ubuntu:14.04
MAINTAINER Gabriel Fernandez <gabrielpfernandez@gmail.com>

RUN apt-get update && apt-get install -y haproxy
RUN apt-get install -y python
RUN apt-get install -y python-pip
RUN pip install Flask
RUN sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/haproxy
RUN rm /etc/haproxy/haproxy.cfg
ADD haproxy.cfg /etc/haproxy
ADD redirect_daemon_main.py /etc/haproxy
ADD attestation_redirect_daemon_main.py /etc/haproxy
ADD start.sh /usr/src
ADD nodes.json /etc/haproxy


RUN sed -i 's/#$ModLoad imudp/$ModLoad imudp/g' /etc/rsyslog.conf && \
    sed -i 's/#$UDPServerRun 514/$UDPServerRun 514/g' /etc/rsyslog.conf && \
    sed -i '/$UDPServerRun 514/a $UDPServerAddress 127.0.0.1' /etc/rsyslog.conf


RUN echo -e 'local0.* -/var/log/haproxy.log\n& ~' > /etc/rsyslog.d/49-haproxy.conf

RUN touch /etc/haproxy/build_log.txt


CMD /etc/init.d/rsyslog start && /etc/init.d/haproxy start && bash /usr/src/start.sh && while true; do sleep 1000; done;
#CMD /etc/init.d/rsyslog start && /etc/init.d/haproxy start && python /etc/haproxy/redirect_daemon_main.py && /etc/haproxy/redirect_daemon.py while true; do sleep 1000; done;
#CMD /etc/init.d/rsyslog start && /etc/init.d/haproxy start && while true; do sleep 1000; done;

#CMD haproxy -f /etc/haproxy/haproxy.cfg && while true; do slepp 1000; done;


