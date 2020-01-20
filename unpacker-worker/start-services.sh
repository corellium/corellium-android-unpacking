#!/bin/bash

# Start the adb server
adb start-server
#--daemon
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start adb: $status"
  exit $status
  exit 99
fi
echo "ADB server started..."

# Start the worker
python3 -u /app/worker.py
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start unpacker workers: $status"
  exit $status
fi

while sleep 60; do
  ps aux | grep adb | grep -q -v grep
  ADB_SERVER=$?
  ps aux | grep worker.py | grep -q -v grep
  UNPACKER_WORKER=$?
  # If the greps above find anything, they exit with 0 status
  # If they are not both 0, then something is wrong
  if [ $ADB_SERVER -ne 0 -o $UNPACKER_WORKER -ne 0 ]; then
    echo "One of the processes has already exited."
    exit 1
  fi
done