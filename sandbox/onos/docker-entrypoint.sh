#!/bin/bash

init_apps() {
    while [ "$(curl --user onos:rocks -s 'localhost:8181/onos/v1/applications/org.onosproject.gui2' | jq -r '.state')" != "ACTIVE" ]
    do
        sleep 1
    done

    for a in $(ls /apps)
    do
        cd /apps/$a
        /root/onos/bin/onos-app localhost install! target/*.oar
    done
    
    for a in $(ls /configs)
    do
        /root/onos/bin/onos-netcfg localhost /configs/$a
    done
}

init_apps &

cd /root/onos

./bin/onos-service server

