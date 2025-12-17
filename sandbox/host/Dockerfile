FROM debian:latest
RUN apt-get update && apt-get -y upgrade 
RUN apt-get install -y lsb-release curl wget iproute2 iputils-ping arping mtr dnsutils python3 python3-pip ssh tcpdump
CMD ["bash", "start.sh"]

