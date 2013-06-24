#!/bin/bash

corevcmd() {
	node=$1
	shift
	vcmd  -c /tmp/$(ls -lt /tmp/ | grep pycore | head -n 1 | awk '{print $NF}')/$node -- $@
}

corevcmd server ip route add default via 192.168.1.2
corevcmd controller ip route add default via 10.100.100.2
corevcmd client ip route add default via 192.168.200.5

