#!/bin/bash

for host in "$@"; do
    printf "Waiting for ${host}..."
    while ! ping -c 1 -n -w 1 ${host} &> /dev/null
    do
        printf "."
        sleep 0.5
    done
    printf "\n"
done

echo "All hosts responded to ping. Exiting."
