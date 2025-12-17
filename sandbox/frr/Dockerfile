FROM debian:latest
RUN apt-get update && apt-get -y upgrade && apt-get install -y lsb-release curl wget gnupg2 iproute2 iputils-ping mtr dnsutils wireguard ssh iptables tcpdump conntrack arping
RUN curl -s https://deb.frrouting.org/frr/keys.gpg > /usr/share/keyrings/frrouting.gpg
ENV FRRVER="frr-stable"
RUN echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr $(lsb_release -s -c) $FRRVER" | tee -a /etc/apt/sources.list.d/frr.list
RUN apt update && apt install -y frr frr-pythontools
RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
