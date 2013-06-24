#!/bin/bash

SERVICENAME="openvswitchservice_start.sh"

corevcmd() {
	node=$1
	shift
	vcmd  -c /tmp/$(ls -lt /tmp/ | grep pycore | head -n 1 | awk '{print $NF}')/$node -- $@
}

for node in /tmp/$(ls -lt /tmp/ | grep pycore | head -n 1 | awk '{print $NF}')/*.pid; do
	nodename=$(basename $node .pid);
	corevcmd $nodename bash $SERVICENAME start
	corevcmd $nodename bash ./o2o.sh > /tmp/${nodename}_o2o.log 2>&1 &
	corevcmd $nodename bash ./emergency_flows.sh > /tmp/${nodename}_emer_flows.log 2>&1 &
done

