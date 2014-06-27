#!/bin/bash

function print_usage() {
	echo "	fripadm version 1.10 by yunthanatos@163.com"
	echo "	fripadm usage: fripadm:find/insert/delete/delete all/switch/rebuild/dump"
	echo "	fripadm_black_in"
	echo "#fripadm insert '192.168.31.98 127.*.*.* 255.*.*.1-100'"
	echo "#fripadm switch"
	echo "#fripadm find 127.3.4.7 "
	echo "#fripadm delete 127.0-255.*.*"
	echo "#fripadm switch"
	echo "#fripadm find 127.3.4.7 "
	echo "#fripadm rebuild 1025 3199"
	echo "#fripadm find 192.168.31.98 "
	echo "#fripadm dump "
	echo "#fripadm dump ip"
	echo "#fripadm dump struct"
	echo "#fripadm dump numbers"
}

if [ "$#" -eq 0 ]
then
	print_usage &>/proc/self/fd/2
	exit 1
fi

if [ "$1" = "find" ]
then
	./fripadm_black_in_exe 2 "$2"
elif [ "$1" = "insert" ] 
then
	./fripadm_black_in_exe 4 "$2"
elif [ "$1" = "delete" ] 
then
	./fripadm_black_in_exe 7 "$2"
elif [ "$1" = "delete all" ] 
then
	./fripadm_black_in_exe 8
elif [ "$1" = "switch" ] 
then
	./fripadm_black_in_exe 9
elif [ "$1" = "rebuild" ] 
then
	./fripadm_black_in_exe 10 "$2" "$3"
elif [ "$1" = "dump" ] 
then
	./fripadm_black_in_exe 12
	if [ "$2" = "" ]
	then
		dmesg | grep frdev_dump_struct | tail -1 | tr $ '\n'
		dmesg | grep frdev_dump_ip | tail -1 | tr $ '\n'
	elif [ "$2" = "ip" ]
	then
		dmesg | grep frdev_dump_ip | tail -1 | tr $ '\n'
	elif [ "$2" = "struct" ]
	then
		dmesg | grep frdev_dump_struct | tail -1 | tr $ '\n'
	elif [ "$2" = "numbers" ]
	then
		dmesg | grep frdev_dump_numbers | tail -1 | tr $ ' '
	else
		print_usage &>/proc/self/fd/2
		exit 1	
	fi	
else
	print_usage &>/proc/self/fd/2
	exit 1	
fi

exit $?
