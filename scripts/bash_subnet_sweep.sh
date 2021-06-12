#!/bin/bash

for host in {1..255}; do
        for port in {1..6535}; do
                timeout .1 bash -c "echo > /dev/tcp/1.1.1.$host/$port" &&
                echo "1.1.1.$host port $port is open"
        done
done
echo "Done"
