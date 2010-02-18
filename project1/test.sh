#!/bin/bash
sudo insmod lkmfirewall.ko
sudo ./fwadmin --in --srcip 128.220.1.1 --destip 255.255.255.255  --srcnetmask 1.3.3.3 --proto TCP --action  BLOCK
