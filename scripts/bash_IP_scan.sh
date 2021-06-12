#!/bin/bash

host=<IP_addresss>
for port in {1..6535}; do
	timeout .1 bash -c "echo > /dev/tcp/$host/$port" &&
		echo "port $port is open"
done
echo "Done"
