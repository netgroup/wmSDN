#!/bin/bash

corevcmd() {
	node=$1
	shift
    echo "command [ $node ]:" $@
	vcmd  -c /tmp/$(ls -lt /tmp/ | grep pycore | head -n 1 | awk '{print $NF}')/$node -- $@
}

IPERF=/usr/bin/iperf
NUMFLOWS=2
OLSRD_DIR=/home/user/wmSDN/olsrd
GWSLEEP=${2:-180}
GW2KILL="gw6"

if [ -z $1 ]; then
        LOGDIR="/tmp/"
else
        LOGDIR=$1
        mkdir -p $LOGDIR
fi

corevcmd server killall iperf
corevcmd client killall iperf

echo "iperf servers"
for i in $( seq 1 $NUMFLOWS ); do
        corevcmd client $IPERF -s -i 2 -f k -p 500${i} > ${LOGDIR}/iperf_s_1${i}.out 2>&1 &
done

for i in $( seq 1 $NUMFLOWS ); do
        echo "iperf client" $i
        corevcmd server $IPERF -c 192.168.200.1${i} -t 900 -p 500${i} > ${LOGDIR}/iperf_1${i}.out 2>&1 &
done

echo $(date -u) "sleeping for $GWSLEEP seconds..."
sleep $GWSLEEP
corevcmd ${GW2KILL} killall olsrd
corevcmd ${GW2KILL} ip link set eth0 down
corevcmd ${GW2KILL} ip link set eth1 down
echo $(date -u) "${GW2KILL} down"

echo $(date -u) "sleeping..."
sleep $GWSLEEP
corevcmd ${GW2KILL} ip link set eth1 up
corevcmd ${GW2KILL} ip link set eth0 up
corevcmd ${GW2KILL} ${OLSRD_DIR}/olsrd -f olsrd.conf -d 1
echo $(date -u) "${GW2KILL} up"

sleep $GWSLEEP

sleep 5


