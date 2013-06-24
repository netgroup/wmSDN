#!/bin/bash

corevcmd() {
	node=$1
	shift
    echo "command [ $node ]:" $@
	vcmd  -c /tmp/$(ls -lt /tmp/ | grep pycore | head -n 1 | awk '{print $NF}')/$node -- $@
}

IPERF=/usr/bin/iperf
SLEEPTIME=20
NUMFLOWS=6

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
        corevcmd client $IPERF -s -i 2 -f k -p 500${i} > ${LOGDIR}/iperf_s_1${i}.log 2>&1 &
done

for i in $( seq 1 $NUMFLOWS ); do
        echo "iperf client" $i
        corevcmd server $IPERF -c 192.168.200.1${i} -t 600 -p 500${i} > ${LOGDIR}/iperf_1${i}.log 2>&1 &
        sleep $SLEEPTIME
done

