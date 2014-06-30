KERNELDIR := /usr/src/linux
PWD := $(shell pwd)
obj-m += ro_trigger.o

all:
	make -C $(KERNELDIR) M=$(PWD) modules
clean:
	rm -fr *.o *.ko *.mod.c
