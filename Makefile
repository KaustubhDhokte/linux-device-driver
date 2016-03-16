obj-m := sdc_driver.o
#obj-m := cache_manager.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

#obj-m := ldd.o
#KDIR := /lib/modules/$(shell uname -r)/build
#PWD := $(shell pwd)
#default:
#	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
