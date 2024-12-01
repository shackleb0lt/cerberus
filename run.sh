#!/bin/bash

set -e
host=${1:-"1.1.1.1"}

make clean
make release
sudo chown root:root bld/cerberus
sudo chmod u+s bld/cerberus

echo "_____________________________________"
bld/cerberus $host
echo "_____________________________________"