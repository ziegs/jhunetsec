CC=gcc
CFLAGS1= -g -std=c99 -O
obj-m += lkmfirewall.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: kmod client

kmod:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
client:
	$(CC) $(CFLAGS1)  fwadmin.c -o fwadmin
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
