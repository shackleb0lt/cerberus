#!/bin/bash

set -e
host=${1:-"1.1.1.1"}

make clean
make release
sudo setcap cap_net_raw+ep bld/cerberus

echo "_____________________________________"
bld/cerberus $host
echo "_____________________________________"
