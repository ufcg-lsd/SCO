FROM ubuntu:14.04
 MAINTAINER Gabriel Fernandez <gabrielpfernandez@gmail.com>
 RUN apt-get update
 RUN apt-get install -y python-pip python-dev build-essential
 COPY . /app
 WORKDIR /app
 RUN pip install Flask
 EXPOSE 5000
 CMD python app.py
 
 
