KERNEL_TARGET=kernel_genl
USER_TARGET=user_genl
obj-m += $(KERNEL_TARGET).o

all: kernel-module-uninstall kernel-clean-ring-buffer kernel-build kernel-clean-temporary kernel-module-install user-build
	@tput setaf 3
	@echo "    done: all"
	@tput sgr0
clean: kernel-module-uninstall kernel-clean user-clean
	@tput setaf 3
	@echo "    done: clean"
	@tput sgr0
 
kernel-build:
	@tput setaf 1
	@echo "    kernel-build"
	@tput sgr0
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
kernel-clean:
	@tput setaf 1
	@echo "    kernel-clean"
	@tput sgr0
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
kernel-clean-temporary:
	@tput setaf 1
	@echo "    kernel-clean-temporary"
	@tput sgr0
	-rm -rf *.o *~ core .depend .*.cmd *.mod.c .tmp_versions
	-rm -rf kern/*.o kern/*~ kern/core kern/.depend kern/.*.cmd kern/*.mod.c kern/.tmp_versions
	-rm -rf Module.symvers modules.order
kernel-module-install:
	@tput setaf 1
	@echo "    kernel-module-install"
	@tput sgr0
	-sudo insmod $(KERNEL_TARGET).ko
kernel-module-uninstall:
	@tput setaf 1
	@echo "    kernel-module-uninstall"
	@tput sgr0
	-sudo rmmod $(KERNEL_TARGET)
kernel-clean-ring-buffer:
	@tput setaf 1
	@echo "    kernel-clean-ring-buffer"
	@tput sgr0
	sudo dmesg -c > /dev/null

 
 
user-build:
	@tput setaf 1
	@echo "    user-build"
	@tput sgr0
	gcc $(USER_TARGET).c -o hello `pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0`
user-clean:
	@tput setaf 1
	@echo "    user-clean"
	@tput sgr0
	rm -rf *.o hello
