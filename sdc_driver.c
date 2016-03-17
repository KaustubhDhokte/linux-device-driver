#include <linux/module.h>
#include <linux/kernel.h> /* printk() */
#include <linux/proc_fs.h>
/* Device specific files*/
#include <linux/genhd.h>
#include <linux/blkdev.h>

/* Thread specific files */
#include <linux/sched.h>  // for task_struct
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/kfifo.h>
#include "cache_manager.h"
#define MAX_BUFFER_SIZE 4096
#define MAXLEN 256

static int major_num = 0;
static int logical_block_size = 512;
static int nsectors = 1024; /* How big the drive is */
int threshold_io_count = 10;
module_param(threshold_io_count, int, 0);
static unsigned int write_io = 0;
static char proc_priv_data[4][8] = {"proc_1", "proc_2", "proc_3", "proc_4"};

struct proc_dir_entry *proc;
static struct request_queue *req_queue;
struct kmem_cache *cache;
struct kfifo cached_requests_fifo;
static struct workqueue_struct *workq;

typedef struct sdc_device_request{
  sector_t sector;
  unsigned long nsect;
  char buffer[MAX_BUFFER_SIZE];
}sdc_device_request;

static struct sdc_device {
	unsigned long size;
	spinlock_t lock;
	u8 *data;
	struct gendisk *gd;
} device;

struct driver_info {
  ssize_t driver_memory; // total memory taken by driver
  ssize_t total_in_memory; // total in memory data
  int batches_flushed; // batches of IO's flushed
  spinlock_t lock; // lock to update fields inside stuct
};

struct driver_info stats;

static void initialize_request(void *buffer)
{
    sdc_device_request *io = (sdc_device_request *)buffer;
    io->sector = 0;
    io->nsect = 0;
}

static void sdc_device_write(struct sdc_device *dev, sdc_device_request *req){
      unsigned long offset = req->sector * logical_block_size;
      unsigned long nbytes = req->nsect * logical_block_size;
      if((offset + nbytes) > dev->size)
      {
	printk(KERN_NOTICE "Device full\n");
	return;
      }
      spin_lock(&(dev->lock));
      memcpy(dev->data + offset, req->buffer, nbytes);
      spin_unlock(&(dev->lock));
      printk(KERN_INFO "Write request completed\n");
}

void flush_io(struct work_struct *work){
  int ret;
  sdc_device_request *req;
  req = (sdc_device_request *)kmem_cache_alloc(cache, GFP_KERNEL);
  printk(KERN_INFO "Flushing queued IOs to disk...\n");
  ret = kfifo_out(&cached_requests_fifo, req, sizeof(sdc_device_request));
  while (ret)
  {
      sdc_device_write(&device, req);
      ret = kfifo_out(&cached_requests_fifo, req, sizeof(sdc_device_request));
  }
  kmem_cache_free(cache, req);
  kfree(work);
  spin_lock(&(stats.lock));
  stats.batches_flushed ++;
  spin_unlock(&(stats.lock));
  write_io = 0;
  printk(KERN_INFO "All queued IOs flushed to the disk \n");
}

static void sdc_request(struct request_queue *q) {
        struct request *req;
	int ret;
	struct work_struct *work;
	sdc_device_request *new_sdc_request;
        req = blk_fetch_request(q);
        while (req != NULL) {
                if (req == NULL || (req->cmd_type != REQ_TYPE_FS)) {
                        printk (KERN_NOTICE "Skip non-CMD request\n");
                        __blk_end_request_all(req, -EIO);
                        continue;
                }
                printk(KERN_DEBUG "New request \n");
		if (rq_data_dir(req)){
		  new_sdc_request = (sdc_device_request *)kmem_cache_alloc(cache, GFP_KERNEL);
		  if (!new_sdc_request)
		  {
		    printk(KERN_ALERT "Failed to allocate new object from cache");
		    return;
		  }
		  printk(KERN_DEBUG "New object allocated from cache");
		  new_sdc_request->sector = blk_rq_pos(req);
		  new_sdc_request->nsect = blk_rq_cur_sectors(req);
		  memcpy(new_sdc_request->buffer, req->buffer, new_sdc_request->nsect*logical_block_size);
		  if (write_io < threshold_io_count){
		    /*Queue the request*/
		    ret = kfifo_in(&cached_requests_fifo, new_sdc_request, sizeof(sdc_device_request));
		    write_io ++;
		    printk(KERN_INFO "Request enqueued.: %d\n", write_io);
		  }
		  if (write_io == threshold_io_count){
		    /*flush the IOs if IOs are reached to their threshold value*/
		    work = (struct work_struct *)kmalloc(sizeof(struct work_struct), GFP_KERNEL);
		    if (work) {
			INIT_WORK(work, flush_io);
			queue_work(workq, work);
			printk(KERN_INFO "Work added to the workqueue\n");
		    }
		   // write_io = 0;
		  }
		  kmem_cache_free(cache, new_sdc_request);
		}
		
                if ( ! __blk_end_request_cur(req, 0) ) {
                        req = blk_fetch_request(q);
                }
        }
}

ssize_t proc_read(struct file *filp, char *buf, size_t count, loff_t *offp)
{
    char *data = NULL;
    int data_len = 0;
    ssize_t size = 0;
    static char op_buf[MAXLEN];
    data = PDE_DATA(file_inode(filp));
    if(!(data)){
	printk(KERN_INFO "Null data");
	return 0;
    }
    if (!strncmp(data, proc_priv_data[1], strlen(proc_priv_data[1]))) {
	sprintf(op_buf, "Batches of IO's fulshed: %d\n", stats.batches_flushed);
	data_len = strlen(op_buf);
	if(count > data_len) {
	  count = data_len;
	}
    count = simple_read_from_buffer(buf, count, offp, op_buf, data_len);
    }
    else {
	/*Do nothing*/
	count = -EINVAL;
    }    
    return count;
}


ssize_t proc_write(struct file *filp, const char *buf, size_t count, loff_t *offp)
{
    char *data = NULL;
    char str[3];
    struct work_struct *work;
    data = PDE_DATA(file_inode(filp));
    if(!(data)){
      printk(KERN_INFO "Null data");
      return 0;
    }
    if (!strncmp(data, proc_priv_data[2], strlen(proc_priv_data[2]))) {
      count = simple_write_to_buffer(str, 1, offp, buf, count) + 1;
      str[1] = '\0';
      if (!strcmp(str, "1"))
      {
	work = (struct work_struct *)kmalloc(sizeof(struct work_struct), GFP_KERNEL);
	if (work) {
	    INIT_WORK(work, flush_io);
	    queue_work(workq, work);
	    printk(KERN_INFO "Work added to the workqueue\n");
	}
      }
      else
	count = -EINVAL;
    }
    else {
      /*Do nothing*/
	count = -EINVAL;
    }
    return count;
}

static const struct file_operations proc_fops = {
  .read = proc_read,
  .write = proc_write
};

/**
* Create proc entries and add data to inode's priv field
*/
void create_proc_entries(void)
{
    proc = proc_create_data("proc_1", S_IRWXU | S_IRWXG | S_IRWXO, NULL, &proc_fops, proc_priv_data[0]);
    proc = proc_create_data("proc_2", S_IRWXU | S_IRWXG | S_IRWXO, NULL, &proc_fops,proc_priv_data[1]);
    proc = proc_create_data("proc_3", S_IRWXU | S_IRWXG | S_IRWXO, NULL, &proc_fops,proc_priv_data[2]);
    proc = proc_create_data("proc_4", S_IRWXU | S_IRWXG | S_IRWXO, NULL, &proc_fops,proc_priv_data[3]);
}
/**
* Removing proc entries
*/
void remove_proc_entries(void)
{
    remove_proc_entry("proc_1", NULL);
    remove_proc_entry("proc_2", NULL);
    remove_proc_entry("proc_3", NULL);
    remove_proc_entry("proc_4", NULL);
}

/*
 * The device operations structure.
 */
static struct block_device_operations sdc_ops = {
                .owner  = THIS_MODULE
};

static int __init sdc_init(void) {
  
	int ret;
	cache = kmem_cache_create("sdc_request_cache", sizeof(sdc_device_request), 0, (SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD|SLAB_NOLEAKTRACE), initialize_request);
	if (cache == NULL)
	{
	  printk(KERN_NOTICE "Failed to create cache.\n");
	  return -ENOMEM;
	}
	printk(KERN_INFO "Cache created for structure sdc_request_cache \n");
	ret = kfifo_alloc(&cached_requests_fifo, threshold_io_count*sizeof(sdc_device_request), GFP_KERNEL);
	if(ret)
	{
	  printk(KERN_NOTICE "Failed to allocate kfifo object\n");
	  return ret;
	}
	printk(KERN_INFO "kfifo object allocated successfully \n");
	workq = create_workqueue("my_queue");
	
	create_proc_entries();
	
	stats.driver_memory = 0;
	stats.total_in_memory = 0;
	stats.batches_flushed = 0;
	spin_lock_init(&stats.lock);
	
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
	kmem_cache_destroy(cache);
	remove_proc_entries();
	printk(KERN_INFO "All cleanup done \n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kaustubh Dhokte");

module_init(sdc_init);
module_exit(sdc_exit);