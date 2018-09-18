FROM ubuntu:14.04
MAINTAINER Gabriel Fernandez <gabrielpfernandez@gmail.com>

RUN apt-get update && apt-get install haproxy
RUN sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/haproxy
RUN rm /etc/haproxy/haproxy.cfg
ADD haproxy.cfg /etc/haproxy
CMD haproxy -f /etc/haproxy/haproxy.cfg && while true; do slepp 1000; done;


