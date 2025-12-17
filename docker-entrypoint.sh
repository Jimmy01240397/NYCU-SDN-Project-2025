#!/bin/sh

pwddir=$(pwd)
rm -f /var/run/docker.pid
dockerd &
/usr/share/openvswitch/scripts/ovs-ctl --no-ovs-vswitchd --no-monitor --system-id=random --no-record-hostname start &
sleep 1s
/usr/share/openvswitch/scripts/ovs-ctl --no-ovsdb-server --no-monitor --system-id=random --no-record-hostname start &
sleep 1s
/usr/share/openvswitch/scripts/ovs-ctl record-hostname-if-not-set
sleep 3s

for a in $(ls images)
do
    docker image load -i images/$a
done

cd /sandbox

/init.sh

for imagename in $(docker images --format "{{.Repository}}:{{.Tag}}")
do
    if ! [ -f $pwddir/images/$(echo "$imagename" | awk -F: '{print $1}' | sed 's/\//_/g').tar ]
    then
        docker image save "$imagename" > $pwddir/images/$(echo "$imagename" | awk -F: '{print $1}' | sed 's/\//_/g').tar
    fi
done

cd $pwddir

sleep inf
