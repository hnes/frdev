# Name

frdev - A high efficient ip black/white firewall (work as a linux kernel module).

Some details could get from [here](http://www.cnblogs.com/SwordTao/p/3824980.html).

# Usage:

```bash
make 
bash install_frdev.sh
ls -hl /dev/frdev*
gcc fripadm_black_in_exe.c -o fripadm_black_in_exe
gcc fripadm_white_in_exe.c -o fripadm_white_in_exe

ping 192.168.31.100 

bash fripadm_black_in.sh insert '192.168.31.100 8.8.8.8 1.100-1.*.1'
bash fripadm_black_in.sh switch
bash fripadm_black_in.sh dump

bash fripadm_white_in.sh insert '192.168.31.100 8.8.8.8 '
bash fripadm_white_in.sh switch
bash fripadm_white_in.sh dump

# # do what you want now :)

bash unstall_frdev.sh
```

# License

Just feel free and do anything you want with it. 

Good luck and Joy!
