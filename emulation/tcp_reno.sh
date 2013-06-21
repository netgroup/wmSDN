#!/bin/bash

echo reno > /proc/sys/net/ipv4/tcp_congestion_control
echo 0 > /proc/sys/net/ipv4/tcp_window_scaling

