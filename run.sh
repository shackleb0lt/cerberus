#!/bin/bash

set -e
host=${1:-"one.one.one.one"}

make clean
make release
sudo setcap cap_net_raw+ep bld/ping
# sudo setcap cap_net_raw+ep bld/tracert

echo "_____________________________________"
bld/ping -c 5 -i 100 $host
echo "_____________________________________"
# bld/tracert $host
# echo "_____________________________________"
