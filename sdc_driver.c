#include "sdc_driver.h"

/**Device statistics*/
static int major_num = 0;
static int logical_block_size = 512;
static int nsectors = 1024;

/** Module parameter*/
static unsigned int THRESHOLD_IO_CNT = 10;
module_param(THRESHOLD_IO_CNT, int, 0);

/** Count of current write requests cached in the memory*/
static unsigned int write_io = 0;
/** Proc entry titles*/
static char proc_priv_data[4][24] = {"sdc_memory_consumption", "sdc_flushed_batches", "sdc_flush_io", "sdc_inmemory_data"};

/** proc entry*/
struct proc_dir_entry *proc;
/** Incoming request queues*/
static struct request_queue *req_queue;
/** slab allocator cache*/
struct kmem_cache *cache;
/** Queue to cache the write requests*/
struct kfifo cached_requests_fifo;
/** WorkQueue structure*/
static struct workqueue_struct *workq;
/** Driver metadata*/
struct driver_info stats;

static void initialize_request(void *buffer)
{
    sdc_device_request *io = (sdc_device_request *)buffer;
    io->sector = 0;
    io->nsect = 0;
}

ssize_t total_in_memory_data(void)
{
  spin_lock(&(stats.lock));
  /** In cache memory = Total size - available memory*/
  stats.total_in_memory = kfifo_size(&cached_requests_fifo) - kfifo_avail(&cached_requests_fifo) ;
  spin_unlock(&(stats.lock));
  return stats.total_in_memory;
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
  int return_value;
  sdc_device_request *req;
  /** Check requests are queued if any, else simply return*/
  if (kfifo_is_empty(&cached_requests_fifo)){
    printk(KERN_WARNING "No pending requests to be flushed\n");
    return;
  }
  /** Allocate memory for popped out request*/
  req = (sdc_device_request *)kmem_cache_alloc(cache, GFP_KERNEL);
  /** Update driver stats*/
  spin_lock(&(stats.lock));
  stats.driver_memory += sizeof(sdc_device_request);
  spin_unlock(&(stats.lock));
  
  printk(KERN_INFO "Flushing cached IOs to disk...\n");
  /** Flush all requests in the queue*/
  return_value = kfifo_out(&cached_requests_fifo, req, sizeof(sdc_device_request));
  while (return_value)
  {
      sdc_device_write(&device, req);
      return_value = kfifo_out(&cached_requests_fifo, req, sizeof(sdc_device_request));
  }
  kmem_cache_free(cache, req);
  kfree(work);
  /** Update driver stats*/
  spin_lock(&(stats.lock));
  stats.driver_memory -= sizeof(sdc_device_request);
  stats.driver_memory -= sizeof(struct work_struct);
  stats.batches_flushed ++;
  spin_unlock(&(stats.lock));
  
  write_io = 0;
  printk(KERN_INFO "All cached IOs flushed to the disk \n");
}

static void sdc_request(struct request_queue *q) {
	/*Request object*/
        struct request *req;
	int return_value;
	struct work_struct *work;
	sdc_device_request *new_sdc_request;
	/*Fetch first scheduled request*/
        req = blk_fetch_request(q);
        while (req != NULL) {
                if (req == NULL || (req->cmd_type != REQ_TYPE_FS)) {
                        printk (KERN_NOTICE "Skip non-CMD request\n");
                        __blk_end_request_all(req, -EIO);
                        continue;
                }
                /** Process if it is a write request*/
		if (rq_data_dir(req)){
		  printk(KERN_DEBUG "Processing new write request\n");
		  /** Allocate new object from the cache*/
		  new_sdc_request = (sdc_device_request *)kmem_cache_alloc(cache, GFP_KERNEL);
		  if (!new_sdc_request)
		  {
		    printk(KERN_ALERT "Failed to allocate new object from cache\n");
		    return;
		  }
		  /** Update driver stats*/
		  spin_lock(&(stats.lock));
		  stats.driver_memory += sizeof(sdc_device_request);
		  spin_unlock(&(stats.lock));

		  printk(KERN_DEBUG "New object allocated from cache\n");
		  /** Get target sector number*/
		  new_sdc_request->sector = blk_rq_pos(req);
		  /** Get number of sectors*/
		  new_sdc_request->nsect = blk_rq_cur_sectors(req);
		  /** Get the contents*/
		  memcpy(new_sdc_request->buffer, req->buffer, new_sdc_request->nsect*logical_block_size);
		  /** Check if threshold is reached*/
		  if (write_io < THRESHOLD_IO_CNT){
		    /*Enqueue the request*/
		    return_value = kfifo_in(&cached_requests_fifo, new_sdc_request, sizeof(sdc_device_request));
		    write_io ++;
		    printk(KERN_INFO "Write Request cached.\n");
		  }
		  if (write_io == THRESHOLD_IO_CNT){
		    /*flush the IOs if IOs are reached to their threshold value*/
		    work = (struct work_struct *)kmalloc(sizeof(struct work_struct), GFP_KERNEL);
		    if (work) {
			/** Update the driver stats*/
			spin_lock(&(stats.lock));
			stats.driver_memory += sizeof(struct work_struct);
			spin_unlock(&(stats.lock));
			/** Init and schedule the IOs to flush in a workqueue*/
			INIT_WORK(work, flush_io);
			queue_work(workq, work);
			printk(KERN_INFO "Cached write requests reached to its threshold value. : [%d]\n Work added to the workqueue\n", THRESHOLD_IO_CNT);
		    }
		  }
		  kmem_cache_free(cache, new_sdc_request);
		  /** Update driver status*/
		  spin_lock(&(stats.lock));
		  stats.driver_memory -= sizeof(sdc_device_request);
		  spin_unlock(&(stats.lock));
		}
		else{
		  printk(KERN_INFO "Received New Read request\n");
		}
		/*Fetch new request*/
                if ( ! __blk_end_request_cur(req, 0) ) {
                        req = blk_fetch_request(q);
                }
        }
}


ssize_t proc_read(struct file *filp, char *buffer, size_t count, loff_t *offp)
{
    char *data = NULL;
    int data_len = 0;
    ssize_t size = 0;
    static char op_buffer[MAXLEN];
    data = PDE_DATA(file_inode(filp));
    if(!(data)){
	printk(KERN_INFO "Null data");
	return 0;
    }
     /* Displays total amount of memory used by driver */
    if (!strncmp(data, proc_priv_data[0], strlen(proc_priv_data[0]))) {
	spin_lock(&(stats.lock));
	sprintf(op_buffer, "Total memory taken by driver: %ld Bytes\n", stats.driver_memory);
	spin_unlock(&(stats.lock));
    } 
    /*Display batches of IOs flushed to the disk*/
    else if (!strncmp(data, proc_priv_data[1], strlen(proc_priv_data[1]))) {
	spin_lock(&(stats.lock));
	sprintf(op_buffer, "Batches of IO's fulshed: %d\n", stats.batches_flushed);
	spin_unlock(&(stats.lock));
    }
    /* Displays total in-memory data*/
    else if (!strncmp(data, proc_priv_data[3], strlen(proc_priv_data[3]))) {
	size = total_in_memory_data();
	sprintf(op_buffer, "Total in-memory data : %ld Bytes \n",(long) size);
    }
    else {
	/*Do nothing*/
	count = -EINVAL;
	return count;
    }
    data_len = strlen(op_buffer);
    if(count > data_len) {
	  count = data_len;
    }
    count = simple_read_from_buffer(buffer, count, offp, op_buffer, data_len);
    return count;
}


ssize_t proc_write(struct file *filp, const char *buffer, size_t count, loff_t *offp)
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
      count = simple_write_to_buffer(str, 1, offp, buffer, count) + 1;
      str[1] = '\0';
      if (!strcmp(str, "1"))
      {
	printk(KERN_INFO "Processing new request to flush the cached IO\n");
	work = (struct work_struct *)kmalloc(sizeof(struct work_struct), GFP_KERNEL);
	if (work) {
	    spin_lock(&(stats.lock));
	    stats.driver_memory += sizeof(struct work_struct);
	    spin_unlock(&(stats.lock));
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
/* Register proc entries operations*/
static const struct file_operations proc_fops = {
  .read = proc_read,
  .write = proc_write
};

/**
* Create proc entries and add data to inode's priv field
*/
void create_proc_entries(void)
{
    proc = proc_create_data("sdc_memory_consumption", S_IRWXU | S_IRWXG | S_IRWXO, NULL, &proc_fops, proc_priv_data[0]);
    proc = proc_create_data("sdc_flushed_batches", S_IRWXU | S_IRWXG | S_IRWXO, NULL, &proc_fops,proc_priv_data[1]);
    proc = proc_create_data("sdc_flush_io", S_IRWXU | S_IRWXG | S_IRWXO, NULL, &proc_fops,proc_priv_data[2]);
    proc = proc_create_data("sdc_inmemory_data", S_IRWXU | S_IRWXG | S_IRWXO, NULL, &proc_fops,proc_priv_data[3]);
}
/**
* Removing proc entries
*/
void remove_proc_entries(void)
{
    remove_proc_entry("sdc_memory_consumption", NULL);
    remove_proc_entry("sdc_flushed_batches", NULL);
    remove_proc_entry("sdc_flush_io", NULL);
    remove_proc_entry("sdc_inmemory_data", NULL);
}

/*
 * The device operations structure.
 */
static struct block_device_operations sdc_ops = {
                .owner  = THIS_MODULE
};

static int __init sdc_init(void) {
  
	int return_value;
	/* initialize driver stats */
	stats.driver_memory = 0;
	stats.total_in_memory = 0;
	stats.batches_flushed = 0;
	spin_lock_init(&stats.lock);
	/* Create cache using slab allocator*/
	cache = kmem_cache_create("sdc_request_cache", sizeof(sdc_device_request), 0, (SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD|SLAB_NOLEAKTRACE), initialize_request);
	if (cache == NULL)
	{
	  printk(KERN_NOTICE "Failed to create cache.\n");
	  return -ENOMEM;
	}
	printk(KERN_INFO "Cache created for structure sdc_request_cache \n");
	/* Allocate a queue to cache the requests*/
	return_value = kfifo_alloc(&cached_requests_fifo, THRESHOLD_IO_CNT*sizeof(sdc_device_request), GFP_KERNEL);
	if(return_value)
	{
	  printk(KERN_NOTICE "Failed to allocate kfifo object\n");
	  return return_value;
	}
	/* Update driver statistics*/
	spin_lock(&(stats.lock));
	stats.driver_memory += kfifo_size(&cached_requests_fifo);
	spin_unlock(&(stats.lock));
	
	printk(KERN_INFO "kfifo object allocated successfully \n");
	
	/* Create workqueue*/
	workq = create_workqueue("my_queue");
	/* Create proc entries*/
	create_proc_entries();
	/* Initialize device*/
        device.size = nsectors * logical_block_size; //Initialize device size
        spin_lock_init(&device.lock); // Initialize device lock
        device.data = vmalloc(device.size); // Allocate data block
        if (device.data == NULL)
                return -ENOMEM;
	/* Update driver stats*/
	spin_lock(&(stats.lock));
	stats.driver_memory += sizeof(device.size);
	spin_unlock(&(stats.lock));
	
	printk(KERN_DEBUG "Device size set to: %lu \n", device.size);
        /* Get a request queue.*/
        req_queue = blk_init_queue(sdc_request, &device.lock);
	if (req_queue == NULL)
		goto out;
        blk_queue_logical_block_size(req_queue, logical_block_size);
        /* Register block device*/
        major_num = register_blkdev(major_num, "sdc");
        if (major_num < 0) {
                printk(KERN_WARNING "sdc: unable to get major number\n");
                goto out;
        }
        printk(KERN_DEBUG "Device registered\n");
        /* Innitialize gendisk structure.*/
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
	printk (KERN_INFO "All driver initialization operations successful\n");
        return 0;

out_unregister:
        unregister_blkdev(major_num, "sdc");
	printk(KERN_NOTICE "Block device unregistered \n");
out:
	/* Free device memory*/
        vfree(device.data);
	/* Update driver stats*/
	spin_lock(&(stats.lock));
	stats.driver_memory -= sizeof(device.size);
	spin_unlock(&(stats.lock));
	
	kfifo_free(&cached_requests_fifo);
	spin_lock(&(stats.lock));
	stats.driver_memory -= kfifo_size(&cached_requests_fifo);
	spin_unlock(&(stats.lock));
	printk(KERN_NOTICE "Failed to initialize \n");
        return -ENOMEM;
}

static void __exit sdc_exit(void)
{
	/* Remove gendisk*/
        del_gendisk(device.gd);
        put_disk(device.gd);
	/* Unregister block device*/
        unregister_blkdev(major_num, "sdc");
	/* Clean the request queue*/
        blk_cleanup_queue(req_queue);
	/* Free the device memory*/
        vfree(device.data);
	/* Update driver stats*/
	spin_lock(&(stats.lock));
	stats.driver_memory -= sizeof(device.size);
	spin_unlock(&(stats.lock));
	/* Uninitialize the cache queue*/
	kfifo_free(&cached_requests_fifo);
	/* Update driver stats*/
	spin_lock(&(stats.lock));
	stats.driver_memory -= kfifo_size(&cached_requests_fifo);
	spin_unlock(&(stats.lock));
	/* Destroy the cache*/
	kmem_cache_destroy(cache);
	/*Remove proc entries*/
	remove_proc_entries();
	printk(KERN_INFO "SDC Driver uninitialized \n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kaustubh Dhokte");

module_init(sdc_init);
module_exit(sdc_exit);