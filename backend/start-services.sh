#!/bin/bash

mkdir -p /dev/net && \
    mknod -m 0666 /dev/net/tun c 10 200

# Start the vpn process
openvpn --config /app/profile.ovpn &
#--daemon
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start openvpn: $status"
  exit $status
  exit 99
fi
echo "Open VPN started..."

# Start the main api
/app/unpack-srv
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start unpack-srv: $status"
  exit $status
fi

while sleep 60; do
  ps aux | grep openvpn | grep -q -v grep
  VPN_STATUS=$?
  ps aux | grep unpack-srv | grep -q -v grep
  UNPACK_SRV=$?
  # If the greps above find anything, they exit with 0 status
  # If they are not both 0, then something is wrong
  if [ $VPN_STATUS -ne 0 -o $UNPACK_SRV -ne 0 ]; then
    echo "One of the processes has already exited."
    exit 1
  fi
done