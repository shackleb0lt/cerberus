#!/bin/bash

set -e
host=${1:-"1.1.1.1"}

make clean
make release
sudo setcap cap_net_raw+ep bld/ping

echo "_____________________________________"
bld/ping $host
echo "_____________________________________"
