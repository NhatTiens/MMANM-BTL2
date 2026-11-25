#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"
validate_pair
new_interface
ip address add 10.77.0.1/24 dev wg0
wg set wg0 listen-port 51820 private-key /keys/private peer "$(cat /keys/peer)" allowed-ips 10.77.0.2/32
ip link set wg0 up
finish_interface
printf '%s\n' 'VPN gateway ready: wg0 / UDP 51820'
