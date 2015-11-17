#include <linux/major.h>

#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/ioctl.h>
#include <linux/mutex.h>
#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/debugfs.h>

#define KERNEL_SECTOR_SIZE 512

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcel Müller <neikos@neikos.email>");
MODULE_DESCRIPTION("A Block Device Driver supported by RDMA");

static int rblk_cnt = 1;
module_param(rblk_cnt, int, 0444);
MODULE_PARM_DESC(rblk_cnt, "number of block devices to initialize (default: 1)");

static int rblk_cap = 1024;
module_param(rblk_cap, int, 0444);
MODULE_PARM_DESC(rblk_cap, "number of bytes to allocate (default: 1MiB)");

static DEFINE_SPINLOCK(rblk_lock);

struct rblk_dev {
    spinlock_t queue_lock;
    struct gendisk* disk;
    u8* buffer;
};

static int rblk_major;

static struct rblk_dev* rblk_d;

static int rblk_ioctl(struct block_device *bdev, fmode_t mode,
        unsigned int cmd, unsigned long arg)
{
    long size;
    printk(KERN_INFO "rblk: Got IOCTL %#x\n", cmd);

    return -ENOTTY;
}

static struct block_device_operations rblk_fops = {
    .owner = THIS_MODULE,
    .ioctl = rblk_ioctl,
};

static void rblk_handle_request(struct request* req) {
    void* src;
    void* dest;
    unsigned long len;
    struct req_iterator iter;
    struct bio_vec bvec;
    unsigned long size = blk_rq_bytes(req);
    unsigned long offset;
    struct rblk_dev* dev = req->rq_disk->private_data;

    printk(KERN_INFO "rblk: About to handle %lu bytes at sector %lu", size,
           req->bio->bi_iter.bi_sector);

    if (req->cmd_type != REQ_TYPE_FS) {
        req->errors++;
        __blk_end_request_all(req, -EIO);
        return;
    }

    offset = req->bio->bi_iter.bi_sector*KERNEL_SECTOR_SIZE;

    rq_for_each_segment(bvec, req, iter) {

        void* kaddr = kmap_atomic(bvec.bv_page);
        if (rq_data_dir(req) == WRITE) {
            dest = dev->buffer+offset;
            src  = kaddr+bvec.bv_offset;
        } else {
            dest = kaddr+bvec.bv_offset;
            src  = dev->buffer+offset;
        }

        len = bvec.bv_offset+bvec.bv_len > rblk_cap
                ? rblk_cap - bvec.bv_offset
                : bvec.bv_len;

        printk(KERN_INFO "rblk: %s %d bytes at %d\n",
                (rq_data_dir(req) == WRITE ? "Writing" : "Reading"),
                len, offset);
        memcpy(dest, src, len);
        kunmap_atomic(kaddr);
        offset += len;
    }

    __blk_end_request_all(req, 0);
}

    static void rblk_request_handler(struct request_queue *q)
__releases(q->queue_lock) __acquires(q->queue_lock)
{
    struct request* req;
    unsigned long flags;

    printk(KERN_INFO "rblk: Got request(s) \n");
    while ((req = blk_fetch_request(q)) != NULL) {
        printk(KERN_INFO "rblk: Handling request \n");
        rblk_handle_request(req);
        printk(KERN_INFO "rblk: Handled request \n");
    }
}

static int __init rblk_init(void)
{
    int i;

    printk(KERN_INFO "rblk: Options: cnt=%d  cap=%d", rblk_cnt, rblk_cap);

    if (rblk_cnt > 16) {
        printk(KERN_ERR "rblk: Trying to allocate more than 16 minor devices.");
        rblk_cnt = 16;
    }

    rblk_major = register_blkdev(0, "rblk");
    if (!rblk_major) {
        printk(KERN_ERR "rblk: Could not registed block device\n");
        return -EINVAL;
    }

    rblk_d = kcalloc(rblk_cnt, sizeof(*rblk_d), GFP_KERNEL);
    if (!rblk_d) {
        printk(KERN_ERR "rblk: Could not allocate memory\n");
        return -ENOMEM;
    }

    for (i = 0; i < rblk_cnt; i++) {
        struct gendisk* disk = alloc_disk(1 << fls(rblk_cnt));
        if (!disk) {
            printk(KERN_ERR "rblk: alloc_disk failure\n");
            goto out_free;
        }
        rblk_d[i].disk = disk;

        disk->queue = blk_init_queue(rblk_request_handler, &rblk_lock);
        if (!disk->queue) {
            printk(KERN_ERR "rblk: Could not init req queue\n");
            put_disk(disk);
            goto out_free;
        }

        rblk_d[i].buffer = kcalloc(1, rblk_cap, GFP_USER);
        if (!rblk_d[i].buffer) {
            printk(KERN_ERR "rblk: Could not alloc buffer\n");
            blk_cleanup_queue(disk->queue);
            put_disk(disk);
            goto out_free;
        }

        // queue_flag_set_unlocked(QUEUE_FLAG_NONROT, disk->queue);
        // queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, disk->queue);
        // disk->queue->limits.discard_granularity = 512;
        // blk_queue_max_discard_sectors(disk->queue, UINT_MAX);
        // disk->queue->limits.discard_zeroes_data = 0;
        // blk_queue_max_hw_sectors(disk->queue, 65536);
        // disk->queue->limits.max_sectors = 256;
        spin_lock_init(&rblk_d[i].queue_lock);
        disk->major = rblk_major;
        disk->first_minor = i << fls(rblk_cnt);
        disk->fops = &rblk_fops;
        disk->private_data = &rblk_d[i];
        sprintf(disk->disk_name, "rblk%d", i);
        add_disk(disk);
        set_capacity(disk, rblk_cap/KERNEL_SECTOR_SIZE);
    }

    return 0;
out_free:
    while(i--) {
        struct gendisk *disk = rblk_d[i].disk;
        if (disk) {
            del_gendisk(disk);
            blk_cleanup_queue(disk->queue);
            put_disk(disk);
        }
        kfree(rblk_d[i].buffer);
    }
    unregister_blkdev(rblk_major, "rblk");
    kfree(rblk_d);

    return -EINVAL;
}

static void __exit rblk_cleanup(void)
{
    int i;

    for (i = 0; i < rblk_cnt; i++) {
        struct gendisk *disk = rblk_d[i].disk;
        if (disk) {
            del_gendisk(disk);
            blk_cleanup_queue(disk->queue);
            put_disk(disk);
        }
        kfree(rblk_d[i].buffer);
    }
    unregister_blkdev(rblk_major, "rblk");
    kfree(rblk_d);
}

module_init(rblk_init);
module_exit(rblk_cleanup);
