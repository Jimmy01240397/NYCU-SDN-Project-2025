FROM onosproject/onos:2.7-latest as builder

RUN apt update && apt install sudo jq maven build-essential bzip2 git unzip zip python3 arping iputils-ping iproute2 mtr -y

COPY install_jdk /install_jdk

RUN bash /install_jdk

COPY apps /apps

RUN bash -c 'for a in $(cat /apps/order.txt); do cd /apps/$a; mvn clean install -DskipTests; done'


FROM onosproject/onos:2.7-latest as release

RUN apt update && apt install sudo jq maven build-essential bzip2 git unzip zip python3 arping iputils-ping iproute2 mtr -y

COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /docker-entrypoint.sh

COPY --from=builder apps /apps

ENTRYPOINT ["/docker-entrypoint.sh"]

