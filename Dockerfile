FROM aminueza/docker-sgx
MAINTAINER Gabriel Fernandez <gabrielpfernandez@gmail.com>


#Installing Docker and Flocker volume drivers
RUN wget -qO- https://get.docker.com/ | sh
RUN apt-get install -y apt-transport-https
#RUN add-apt-repository -y "deb https://clusterhq-archive.s3.amazonaws.com/ubuntu/$(lsb_release --release --short)/\$(ARCH) /"
RUN cat <<EOF > /tmp/apt-pref
RUN mv /tmp/apt-pref /etc/apt/preferences.d/buildbot-700
RUN apt-get update
#RUN apt-get -y install --force-yes clusterhq-flocker-cli

#installing python, pip and virtualenv.
RUN apt-get install -y python && apt-get install -y python-pip
RUN pip install Flask
RUN pip install poster
RUN apt-get install -y curl
ADD secure-container-orchestrator /usr/src/secure-container-orchestrator
ADD assets /usr/src/assets
WORKDIR /usr/src/secure-container-orchestrator/src

#RUN chmod -R ugo+rX /lib/python2.7/site-packages/
#installing web componentes (flask for server, curl for client role)
#exposing port and runnning server application

### REMOVE for non-production envs###
#adding client code
ADD sco-client /usr/src/sco-client
ADD samples /usr/src/samples

#Adding docker login credentials and script
ADD credentials.tmp /usr/src
ADD login.sh /usr/src
#Adding auto-scaling monitor start script
ADD start-monitor.sh /usr/src


#EXPOSE 5000
CMD /bin/bash /usr/src/login.sh &&  /bin/bash /usr/src/start-monitor.sh && python app.py && while true; do sleep 100; done

