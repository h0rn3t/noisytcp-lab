# Lab instrumentation: preemption emulator for the CVE-2026-99288 race window.
#   make && sudo insmod noisyjit.ko period_us=20 burn_us=8 burn_cpu=0
obj-m := noisyjit.o
KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
