Android-Syscall-Logger
---

​	A kernel module that hook some of your system call on your Android Device by rewriting  syscall table.

Prerequisite
---

- pixel 1
- android-8.1.0_r1 == OPM1.171019.011
- Root Access
- Set CONFIG_DEBUG_RODATA to false so you are allowable to rewrite the syscall table.

Environment
---

- I personly recommend you use Kali Linux as I do, since it look way damn good than Ubuntu

Reconfig Your kernel first
---

- Change Directory to your kernel(suppose you kernel folder is located like this ~/aosp810r1/kernel/msm/), then use the following command below. Wrap them inside a script if you prefer.
- ************************************************************************************************
- export ARCH=arm64 &&
- export PATH=~/aosp810r1/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin:$PATH &&
- export CROSS_COMPILE=aarch64-linux-android- &&
- make menuconfig
- ************************************************************************************************
- A Gui based menu will pop up on you screen. 
- ![5](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/7.png)
- I recommend you use the following setings as I do.
- CONFIG_MODULES=Y
- CONFIG_STRICT_MEMORY_RWX=N / CONFIG_DEBUG_RODATA=N
- CONFIG_DEVMEM=Y
- CONFIG_DEVKMEM=Y
- CONFIG_KALLSYMS=Y
- CONFIG_KALLSYMS_ALL=Y
- CONFIG_HAVE_KPROBES=Y
- CONFIG_HAVE_KRETPROBES=Y
- CONFIG_HAVE_FUNCTION_TRACER=Y
- CONFIG_HAVE_FUNCTION_GRAPH_TRACER=Y
- CONFIG_TRACING=Y
- CONFIG_FTRACE=Y
- ************************************************************************************************
- You might ask how to find each of these settings? Tab / , and you shall see a search bar upcoming. Copy it, paste it, and find it.
- ![8](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/8.png)
- ![9](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/9.png)
- Once you finish your editing, run make command again which would create a kernel Image and then flash it to your device. 
- ![10](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/10.png)	
- Like this:
- ![11](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/11.png)
- Check if your kernel is modified.
- ![13](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/13.png)
## Compile & Usage


1. Excellent, I suppose you have reconfigured your kernel already. We can finally launch our missile~
2. First of all, let take a little adjustment on your Makefile
3. ![1](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/1.png)
4. Reset your sys_call_table address by reading /proc/kallsyms, if it shows 0 to you. [echo 0 > /proc/sys/kernel/kptr_restrict] should reveal their true address instead of 0.
5. ![6](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/6.png)
6. Run make to compile the code. Which it should create a file that ends with .ko, that's your kernel module.
7. push kernel module to a certain directory at your phone.
8. ![2](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/2.png)
9. Initialize your module immediately by using [insmod xxxx.ko]
10. ![3](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/3.png)
11. Starting monitoring your log from kernel by using [dmesg -w | grep "myLog"]
12. ![4](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/4.png)
13. Enjoy your pleasure.
14. ![5](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/5.png)

## FAQ
- where I place my project and my kernel?
![14](https://github.com/Katana-O/Android-Syscall-Logger/blob/main/images/14.png)

## Credits
- https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04c-Tampering-and-Reverse-Engineering.md
- https://www.anquanke.com/post/id/199898
- https://github.com/invictus1306/Android-syscall-monitor
- https://www.cnblogs.com/lanrenxinxin/p/6289436.html
