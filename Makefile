ifneq ($(KERNELRELEASE),)
obj-m := incognito.o
else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)
all: incognito command
incognito:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	gcc -o command command_handler.c
command:
	gcc -o command command_handler.c
endif
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
