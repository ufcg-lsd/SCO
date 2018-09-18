FROM ubuntu:14.04
MAINTAINER Gabriel Fernandez <gabrielpfernandez@gmail.com>

ADD ./app.py /usr/src/
WORKDIR /usr/src
RUN apt-get update && apt-get install -y python && apt-get install -y python-pip && pip install Flask
CMD python ./app.py


