#!/bin/bash

SERVICENAME="olsrdservice_start.sh"

corevcmd() {
	node=$1
	shift
	vcmd  -c /tmp/$(ls -lt /tmp/ | grep pycore | head -n 1 | awk '{print $NF}')/$node -- $@
}

for node in /tmp/$(ls -lt /tmp/ | grep pycore | head -n 1 | awk '{print $NF}')/*.pid; do
	nodename=$(basename $node .pid);
	corevcmd $nodename bash $SERVICENAME start
done

