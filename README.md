Android-Syscall-Logger
---

​	A kernel module that hook some of your system call on your Android Device by rewriting syscall table.

Prerequisite
---

- Supported Devices: Pixel(Tested), Pixel 2 XL, Pixel 2, Pixel XL, Pixel C, Nexus 6P, Nexus 5X
- android-8.1.0_r1 == OPM1.171019.011
- Root Access
- Set CONFIG_DEBUG_RODATA to false so you are allowable to rewrite the syscall table.

Testing Environment
---

Advantage
---

- capturing your prefer syscall on a breathing device, lower the posibility of being detected comparing to emulator(unicorn)

Reconfig Your kernel first

Compile & Usage
---

## FAQ

## Credits
- https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04c-Tampering-and-Reverse-Engineering.md
- https://www.anquanke.com/post/id/199898
- https://github.com/invictus1306/Android-syscall-monitor
- https://www.cnblogs.com/lanrenxinxin/p/6289436.html
