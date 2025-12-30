FROM debian:bookworm
RUN apt-get update && apt-get install -y lsb-release curl wget gnupg2 iproute2 iputils-ping mtr dnsutils wireguard ssh iptables tcpdump conntrack arping frr frr-pythontools
RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
