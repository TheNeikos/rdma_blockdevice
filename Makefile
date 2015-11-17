obj-m += rdma_blkd.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insert: all
	sudo insmod ./rdma_blkd.ko

remove:
	sudo rmmod rdma_blkd
