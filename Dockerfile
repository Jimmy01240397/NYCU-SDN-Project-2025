FROM debian:latest

RUN apt-get update && apt-get -y upgrade && apt-get install -y lsb-release curl wget gnupg2 iproute2 iputils-ping mtr dnsutils wireguard ssh iptables tcpdump conntrack openvswitch-switch ovn-central ovn-host bridge-utils

RUN bash -c 'bash <(curl -fsSL https://get.docker.com) --version 28.3'

COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
