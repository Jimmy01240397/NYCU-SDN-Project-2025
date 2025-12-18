#!/bin/bash

wg-quick up wg

ovs-vsctl add-br ovs1 -- set bridge ovs1 protocols=OpenFlow14 -- set-controller ovs1 tcp:${CONTROL_PREFIX_V4}.10:6653 -- set-fail-mode ovs1 secure
ovs-vsctl add-br ovs2 -- set bridge ovs2 protocols=OpenFlow14 -- set-controller ovs2 tcp:${CONTROL_PREFIX_V4}.10:6653 -- set-fail-mode ovs2 secure

ip link set dev ovs1 up
ip link set dev ovs2 up

export ID="$(cat /etc/wireguard/wg.conf | grep -oP '(?<=Address = ).*(?=/)' | awk -F. '{print $4}')"
export TAPREFIX="$(cat /etc/wireguard/wg.conf | grep -oP '(?<=AllowedIPs = ).*(?=/)' | sed 's/\.[^.]*$//g')"

ovs-vsctl add-port ovs2 tota -- set interface tota type=vxlan options:remote_ip=${TAPREFIX}.${ID}

if [ "${LEFT_VNI}" != "" ]
then
    ovs-vsctl add-port ovs2 toleft -- set interface toleft type=vxlan options:remote_ip=${LEFT_REMOTE_IP} options:key=${LEFT_VNI}
fi
if [ "${RIGHT_VNI}" != "" ]
then
    ovs-vsctl add-port ovs2 toright -- set interface toright type=vxlan options:remote_ip=${RIGHT_REMOTE_IP} options:key=${RIGHT_VNI}
fi

ip link add ovs1toovs2 type veth peer name ovs2toovs1
ip link set ovs1toovs2 up
ip link set ovs2toovs1 up

ovs-vsctl add-port ovs1 ovs1toovs2
ovs-vsctl add-port ovs2 ovs2toovs1

cp -r /sandbox/onos/configs/ /tmp/configs

for a in $(ls /tmp/configs)
do
    for b in ovs1 ovs2
    do
        ovsid="of:$(ovs-vsctl get bridge $b datapath_id | sed 's/"//g')"
        sed -i "s=$b=$ovsid=g" "/tmp/configs/$a"
    done
    for b in $(env)
    do
        key="${b%%=*}"
        value="${b#*=}"
        key_esc=$(printf '%s' "${key}" | sed 's/[.[\*^$\/]/\\&/g')
        search="\${${key_esc}}"
        val_esc=$(printf '%s' "${value}" | sed 's/[&/]/\\&/g')
        sed -i "s/${search}/${val_esc}/g" "/tmp/configs/$a"
    done
done

mkdir -p /tmp/routeserver
cp -r /sandbox/routeserver/frr/ /tmp/routeserver/frr

for a in $(ls /tmp/routeserver/frr)
do
    for b in $(env)
    do
        key="${b%%=*}"
        value="${b#*=}"
        key_esc=$(printf '%s' "${key}" | sed 's/[.[\*^$\/]/\\&/g')
        search="\${${key_esc}}"
        val_esc=$(printf '%s' "${value}" | sed 's/[&/]/\\&/g')
        sed -i "s/${search}/${val_esc}/g" "/tmp/routeserver/frr/$a"
    done
done

docker compose -p sandbox up -d

ip link add ovs2tobr type veth peer name brtoovs2
ip link set ovs2tobr up
ip link set brtoovs2 up
ovs-vsctl add-port ovs2 ovs2tobr
brctl addif br-$(docker network ls | grep 'sandbox_control' | awk '{print $1}') brtoovs2

ebtables -A FORWARD -o brtoovs2 -p arp --arp-ip-src ${CONTROL_PREFIX_V4}.10 -j DROP

ovs-docker add-port ovs2 eth0 sandbox-host1-1 --ipaddress=${LAN_PREFIX_V4}.${ID}.2/24 --gateway=${LAN_PREFIX_V4}.${ID}.1
docker compose exec host1 ip link set eth0 mtu ${MTU}
docker compose exec host1 ip -6 addr add ${LAN_PREFIX_V6}:${ID}::2/64 dev eth0
docker compose exec host1 ip -6 route add default via ${LAN_PREFIX_V6}:${ID}::1 dev eth0

ovs-docker add-port ovs1 eth0 sandbox-host2-1 --ipaddress=${LAN_PREFIX_V4}.${ID}.3/24 --gateway=${LAN_PREFIX_V4}.${ID}.1
docker compose exec host2 ip link set eth0 mtu ${MTU}
docker compose exec host2 ip -6 addr add ${LAN_PREFIX_V6}:${ID}::3/64 dev eth0
docker compose exec host2 ip -6 route add default via ${LAN_PREFIX_V6}:${ID}::1 dev eth0

ovs-docker add-port ovs1 eth0 sandbox-routeserver-1 --ipaddress=${LAN_PREFIX_V4}.${ID}.69/24 --gateway=${LAN_PREFIX_V4}.${ID}.1
docker compose exec routeserver ip link set eth0 mtu ${MTU}
docker compose exec routeserver ip -4 addr add ${TRANSIT_LINK_PREFIX_V4}.1/24 dev eth0
docker compose exec routeserver ip -4 addr add ${IX_PREFIX_V4}.${ID}/24 dev eth0
docker compose exec routeserver ip -4 addr add ${CONTROL_PREFIX_V4}.3/24 dev eth0
docker compose exec routeserver ip -6 addr add ${TRANSIT_LINK_PREFIX_V6}::1/64 dev eth0
docker compose exec routeserver ip -6 addr add ${IX_PREFIX_V6}::${ID}/64 dev eth0
docker compose exec routeserver ip -6 addr add ${LAN_PREFIX_V6}:${ID}::69/64 dev eth0
docker compose exec routeserver ip -6 route add default via ${LAN_PREFIX_V6}:${ID}::1 dev eth0

if [ "${LEFT_VNI}" != "" ]
then
    docker compose exec routeserver ip -4 addr add ${LEFT_IP_V4}/24 dev eth0
    docker compose exec routeserver ip -6 addr add ${LEFT_IP_V6}/64 dev eth0
fi
if [ "${RIGHT_VNI}" != "" ]
then
    docker compose exec routeserver ip -4 addr add ${RIGHT_IP_V4}/24 dev eth0
    docker compose exec routeserver ip -6 addr add ${RIGHT_IP_V6}/64 dev eth0
fi

ovs-docker add-port ovs1 eth1 sandbox-transitrouter-1 --ipaddress=${TRANSIT_LINK_PREFIX_V4}.2/24
docker compose exec transitrouter ip link set eth1 mtu ${MTU}
docker compose exec transitrouter ip -6 addr add ${TRANSIT_LINK_PREFIX_V6}::2/64 dev eth1



