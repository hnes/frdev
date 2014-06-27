#!/bin/sh
module="frdev"
device="frdev"

# invoke rmmod with all arguments we got
/sbin/rmmod $module $* || exit 1

# remove nodes
rm -f /dev/${device}[0-1] /dev/${device}

exit 0

