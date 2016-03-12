#include <linux/module.h>
#include <linux/kernel.h> /* printk() */

/* Device specific files*/
#include <linux/genhd.h>
#include <linux/blkdev.h>

/* Thread specific files */
#include <linux/sched.h>  // for task_struct
#include <linux/delay.h>
#include <linux/workqueue.h>



static int major_num = 0;
static int logical_block_size = 512;
static int nsectors = 1024; /* How big the drive is */
int threshold_io_count = 0;
module_param(threshold_io_count, int, 0);

static struct request_queue *req_queue;
static struct sdc_device {
	unsigned long size;
	spinlock_t lock;
	u8 *data;
	struct gendisk *gd;
} device;



static void sdc_request(struct request_queue *q) {
        struct request *req;
        req = blk_fetch_request(q);
        while (req != NULL) {
                if (req == NULL || (req->cmd_type != REQ_TYPE_FS)) {
                        printk (KERN_NOTICE "Skip non-CMD request\n");
                        __blk_end_request_all(req, -EIO);
                        continue;
                }
                printk(KERN_DEBUG "New request \n");
		/*sdc_transfer(&device, blk_rq_pos(req),
			     blk_rq_cur_sectors(req), req->buffer,
			     rq_data_dir(req));*/
                if ( ! __blk_end_request_cur(req, 0) ) {
                        req = blk_fetch_request(q);
                }
        }
}

/*
 * The device operations structure.
 */
static struct block_device_operations sdc_ops = {
                .owner  = THIS_MODULE
};

static int __init sdc_init(void) {

        
        
        device.size = nsectors * logical_block_size;
        spin_lock_init(&device.lock);
        device.data = vmalloc(device.size);
        if (device.data == NULL)
                return -ENOMEM;
	printk(KERN_DEBUG "Device size set to: %lu \n", device.size);
        /*
         * Get a request queue.
         */
        req_queue = blk_init_queue(sdc_request, &device.lock);
	if (req_queue == NULL)
		goto out;
        blk_queue_logical_block_size(req_queue, logical_block_size);
        /*
         * Get registered.
         */
        major_num = register_blkdev(major_num, "sdc");
        if (major_num < 0) {
                printk(KERN_WARNING "sdc: unable to get major number\n");
                goto out;
        }
        printk(KERN_DEBUG "Device registered\n");
        /*
         * And the gendisk structure.
         */
        device.gd = alloc_disk(16);
        if (!device.gd)
                goto out_unregister;
        device.gd->major = major_num;
        device.gd->first_minor = 0;
        device.gd->fops = &sdc_ops;
        device.gd->private_data = &device;
        strcpy(device.gd->disk_name, "sdc0");
        set_capacity(device.gd, nsectors);
        device.gd->queue = req_queue;
        add_disk(device.gd);
        printk (KERN_INFO "init successful\n");
        return 0;

out_unregister:
        unregister_blkdev(major_num, "sdc");
	printk(KERN_NOTICE "Block device unregistered \n");
out:
        vfree(device.data);
	printk(KERN_NOTICE "Failed to initialize \n");
        return -ENOMEM;
}

static void __exit sdc_exit(void)
{
        del_gendisk(device.gd);
        put_disk(device.gd);
        unregister_blkdev(major_num, "sdc");
        blk_cleanup_queue(req_queue);
        vfree(device.data);
	printk(KERN_INFO "All cleanup done \n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kaustubh Dhokte");

module_init(sdc_init);
module_exit(sdc_exit);
