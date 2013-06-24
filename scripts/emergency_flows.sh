#!/bin/bash
#
#  Copyright 2013 Claudio Pisa, Andrea Detti
#
#  This file is part of wmSDN
#
#  wmSDN is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  wmSDN is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with wmSDN.  If not, see <http://www.gnu.org/licenses/>.
#

OLSR_TABLE=198
OLSR_DEFAULT_TABLE=199
SLEEP_TIME=1
OFCTL_DIR=/home/user/wmSDN/openvswitch/utilities
CLIENT_HNA_PATTERN="192\.168\."  # to tell client subnets
SPECIALMACADDRESS="04:0f:04:0f:04:0f"

#every how many loops Openflow rules from the OLSR table are refreshed
RECHECK_OLSR_TABLE_COUNTER=30 

export OPENVSWITCH_DIR=/home/user/wmSDN/openvswitch
export OVS_RUNDIR="$(pwd)"
export OVS_LOGDIR="$(pwd)"

# print and execute a command
printandexec () {
		echo "$@"
		eval "$@"
}

# return a MAC address given an IPv4 address
ip2mac () {
		# TODO: get MAC addresses from OLSR
		#echo $1 | awk -F "." '{ printf ("00:00:00:cc:00:%02x", $4) }'
		echo $1 | awk -F "." '{ printf ("00:00:00:00:00:%02x", $4) }'
}


is_client_hna () {
        # wether the provided routing table entry relates to a client HNA
		DESTINATION=$( echo $1 | awk '{print $1}' | cut -d "/" -f 1 )
        if echo $DESTINATION | grep $CLIENT_HNA_PATTERN; then
                return 0  # true
        else
                return 1  # false
        fi
}

is_gateway() {
    # ASSUMING ALL AND ONLY GATEWAY HOSTNAMES BEGIN WITH "g"
    if [ ${HOSTNAME:0:1} == "g" ]; then
        return 0   #true
    else
        return 1   #false
    fi
}

BR0_IP=$( ip -4 addr show dev br0 | grep -m 1 "inet " | awk '{print $2}' | cut -d "/" -f 1 )
ETH1_IP=$( ip -4 addr show dev eth1 | grep -m 1 "inet " | awk '{print $2}' | cut -d "/" -f 1 )
# assuming /24 TODO: change it to use the real netmask
ETH1_HNA=$( echo "$ETH1_IP" | awk -F '.' '{ print $1 "." $2 "." $3 "." 0 "/24" }' )
LOCALETHMAC=$( ip link sh dev eth0 | grep ether | awk '{print $2}' )
LOCALETH1MAC=$( ip link sh dev eth1 | grep ether | awk '{print $2}' )
LOCALBR0MAC=$( ip link sh dev br0 | grep ether | awk '{print $2}' )
BRD_MAC="ff:ff:ff:ff:ff:ff"

# find port numbers
ETH0PORT=$( ${OFCTL_DIR}/ovs-ofctl show br0 | grep "eth0" | awk '{print $1}' | cut -d "(" -f 1 )
ETH1PORT=$( ${OFCTL_DIR}/ovs-ofctl show br0 | grep "eth1" | awk '{print $1}' | cut -d "(" -f 1 )
#BR0PORT=$( ${OFCTL_DIR}/ovs-ofctl show br0 | grep "br0" | awk '{print $1}' | cut -d "(" -f 1 )
BR0PORT=LOCAL
IN_PORT=0xfff8  # 0xfff8 means output from the same port the packet came from

# translate an IPv4 route entry into an OpenFlow rule
iproute2ofrule () {
		# Usage:
		# iproute2ofrule <in_port> <action> <match_src_mac> <route entry>
		IN_PORT=$1
		shift
		OUT_ACTION=$1
		shift
		# source MAC address to be matched
		SRC_MAC=$1
		shift
		line="$@"
        echo "parameters: " $IN_PORT "," $OUT_ACTION "," $SRC_MAC "," $line > /dev/stderr
		COMPLETEDESTINATION=$( echo $line | awk '{print $1}' )
		DESTINATION=$( echo $COMPLETEDESTINATION | cut -d "/" -f 1 )
		if echo "$COMPLETEDESTINATION" | grep "/" > /dev/null; then
				NETMASK=$(echo $line | awk '{print $1}' | cut -d "/" -f 2)
		else
				if [ "$DESTINATION" == "default" ]; then
						DESTINATION='*'
						NETMASK=32
				else
						NETMASK=32
				fi
		fi
		NEXTHOP=$( echo $line | awk -F "via " '{print $2}' | cut -d " " -f 1 )
		NEXTMAC=$( ip2mac "${NEXTHOP}" )
		if [ $NEXTMAC == "00:00:00:cc:00:00" ]; then
				# no action
				OFRULE="bogus"
		else
				if [ $NETMASK == "32" ]; then
						OFRULE="dl_dst=${SRC_MAC},in_port=${IN_PORT},dl_type=0x800,nw_dst=${DESTINATION},actions=mod_dl_dst:${NEXTMAC},mod_dl_src:${LOCALETHMAC},${OUT_ACTION}"
				else
						OFRULE="dl_dst=${SRC_MAC},in_port=${IN_PORT},dl_type=0x800,nw_dst=${DESTINATION}/${NETMASK},actions=mod_dl_dst:${NEXTMAC},mod_dl_src:${LOCALETHMAC},${OUT_ACTION}"
				fi
		fi
		echo $OFRULE
}

iproutedestination () {
		line="$@"
		COMPLETEDESTINATION=$( echo $line | awk '{print $1}' )
		DESTINATION=$( echo $COMPLETEDESTINATION | cut -d "/" -f 1 )
		if echo "$COMPLETEDESTINATION" | grep "/" > /dev/null; then
				NETMASK=$(echo $line | awk '{print $1}' | cut -d "/" -f 2)
		else
				if [ "$DESTINATION" == "default" ]; then
						DESTINATION="0.0.0.0"
						NETMASK=0
				else
						NETMASK=32
				fi
		fi
		echo ${DESTINATION}/${NETMASK}
}

iproute2neigh () {
		line="$@"
		DESTNM=$( iproutedestination $line)
		DESTINATION=$( echo $DESTNM | cut -d "/" -f 1 )
		NETMASK=$( echo $DESTNM | cut -d "/" -f 2 )

		NEXTHOP=$( echo $line | awk -F "via " '{print $2}' | cut -d " " -f 1 )
		NEXTMAC=$( ip2mac "${NEXTHOP}" )
		if [ $NETMASK == "32" ]; then
				echo "${DESTINATION} lladdr ${NEXTMAC}"
		else
				# no ARP cache entry for subnets
				echo "bogus"
		fi
}

iscontrollerreachable () {
        ${OPENVSWITCH_DIR}/utilities/ovs-vsctl show | grep "is_connected.*true"
}

# main
routepri=5
routepri_hna=7
emergencystatus=false
checkcounter=0

while [ 1 ]; do
        if $emergencystatus && iscontrollerreachable; then
                # controller is reachable, delete emergency flows
                printandexec sleep 3
                ${OFCTL_DIR}/ovs-ofctl del-flows br0 cookie=0x0e/0xff
                emergencystatus=false
                checkcounter=0
        elif ! $emergencystatus && ! iscontrollerreachable; then
                # insert emergency flows
                if [ $(ip -4 -f inet route sh table $OLSR_DEFAULT_TABLE | wc -l) -gt 0 ]; then
                        ip -4 -f inet route sh table $OLSR_DEFAULT_TABLE | (
                            read line # assuming we get only one default route from OLSR
                            # forward packets coming from the wireless interface
                            OFRULE=$( iproute2ofrule $ETH0PORT "output:${IN_PORT}" $LOCALETHMAC $line )
                            printandexec ${OFCTL_DIR}/ovs-ofctl add-flow br0 hard_timeout=0,idle_timeout=0,priority=${routepri},cookie=0xe,${OFRULE}
                            # let out packets generated by us
                            OFRULE=$( iproute2ofrule $BR0PORT "output:${ETH0PORT}" $SPECIALMACADDRESS $line )
                            printandexec ${OFCTL_DIR}/ovs-ofctl add-flow br0 hard_timeout=0,idle_timeout=0,priority=${routepri},cookie=0xe,${OFRULE}
                        )
                elif is_gateway; then
                    printandexec ${OFCTL_DIR}/ovs-ofctl add-flow br0 hard_timeout=0,idle_timeout=0,priority=${routepri},cookie=0xe,dl_type=0x800,actions=mod_dl_dst:${LOCALBR0MAC},local
                fi
                # insert client HNA subnets into the flow table
                ip -4 -f inet route sh table $OLSR_TABLE | (
                        while read line; do
                                # only convert lines related to client HNAs
                                if ! is_client_hna $line; then
                                        continue
                                fi
                                echo "LINE: $line" 1>&2
                                # forward packets coming from the wireless interface
                                OFRULE=$( iproute2ofrule $ETH0PORT "output:${IN_PORT}" $LOCALETHMAC $line )
                                printandexec ${OFCTL_DIR}/ovs-ofctl add-flow br0 hard_timeout=0,idle_timeout=0,priority=${routepri_hna},cookie=0xe,${OFRULE}
                                # let out packets generated by us
                                OFRULE=$( iproute2ofrule $BR0PORT "output:${ETH0PORT}" $SPECIALMACADDRESS $line )
                                printandexec ${OFCTL_DIR}/ovs-ofctl add-flow br0 hard_timeout=0,idle_timeout=0,priority=${routepri_hna},cookie=0xe,${OFRULE}
                        done
                )
                # delete controller flows 
                ${OFCTL_DIR}/ovs-ofctl del-flows br0 cookie=0x0c/0xff
                emergencystatus=true
                checkcounter=0
        elif $emergencystatus; then
                if [ $checkcounter -ge $RECHECK_OLSR_TABLE_COUNTER ]; then
                        emergencystatus=false #recheck the OLSR table periodically
                fi
                ((checkcounter++))
        fi
        printandexec sleep $SLEEP_TIME 
        echo "state of emergency: " $emergencystatus
done


