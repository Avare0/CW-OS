KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += ftrace_hook.o

ftrace_hook:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
