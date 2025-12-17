FROM onosproject/onos:2.7-latest

RUN apt update && apt install sudo jq maven build-essential bzip2 git unzip zip python3 arping iputils-ping iproute2 -y

COPY install_jdk /install_jdk

RUN bash /install_jdk

COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /docker-entrypoint.sh

COPY apps /apps

RUN bash -c 'for a in $(ls /apps); do cd /apps/$a; mvn clean install -DskipTests; done'

ENTRYPOINT ["/docker-entrypoint.sh"]

