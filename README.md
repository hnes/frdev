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

# Notes:

The little patch below will solve the compiling problem in `3.10.0-327.el7.x86_64` (because of the recently kernel updates).

```
diff --git a/frdev.c b/frdev.c
index e60ea8b..0c36a3b 100644
--- a/frdev.c
+++ b/frdev.c
@@ -8,7 +8,7 @@
 #include <linux/init.h>
 #include <linux/cdev.h>
 #include <asm/io.h>
-#include <asm/system.h>
+#include <asm/switch_to.h>
 #include <asm/uaccess.h>
 #include <linux/ioctl.h>
 #include <linux/jiffies.h>
@@ -2042,7 +2042,7 @@ static const struct file_operations fr_ip_mem_fops =
   .owner = THIS_MODULE,
   .open = fr_ip_mem_open,
   .release = fr_ip_mem_release,
-  .ioctl = fr_ip_memdev_ioctl,
+  .unlocked_ioctl = fr_ip_memdev_ioctl,
 };
```

# License

Just feel free and do anything you want with it. 

Good luck and Joy!
