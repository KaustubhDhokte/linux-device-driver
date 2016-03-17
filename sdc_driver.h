#include <linux/module.h>
#include <linux/kernel.h> /* printk() */
#include <linux/proc_fs.h>
/* Device specific files*/
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/kfifo.h>

#define MAX_BUFFER_SIZE 4096
#define MAXLEN 256

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

