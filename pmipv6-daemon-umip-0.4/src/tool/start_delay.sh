#!/bin/sh
ip6tables -t mangle -A PREROUTING -d 2001:100:10:8:e2b9:a5ff:fe83:7f41 -p udp --dport 9079:9080 -j QUEUE
./delay 
