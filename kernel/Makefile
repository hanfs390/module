obj-m := hello.o
KERNELBUILD :=/lib/modules/$(shell uname -r)/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions






#KERNELBUILD :=/lib/modules/$(shell uname -r)/build是编译内核模块需要的Makefile的路径，Ubuntu下是
#/lib/modules/2.6.31-14-generic/build
#make -C $(KERNELBUILD) M=$(shell pwd) modules 编译内核模块。－C 将工作目录转到KERNELBUILD，调用该目录下的Makefile，并向这个Makefile传递参数M的值是$(shell pwd) modules。
