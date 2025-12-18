#!/bin/bash

if [ "${GATEWAY_V4}" != "" ]
then
    ip -4 route add default via ${GATEWAY_V4} dev ${GATEWAY_IFACE}
fi

if [ "${GATEWAY_V6}" != "" ]
then
    ip -6 route add default via ${GATEWAY_V6} dev ${GATEWAY_IFACE}
fi

sleep inf

