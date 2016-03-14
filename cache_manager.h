#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/slab.h>


void *allocate_cache(struct kmem_cache *cachep, gfp_t flags);

struct kmem_cache *create_cache(const char *name, size_t size, size_t align, unsigned long flags, void(*ctor)(void *));

void free_cache(struct kmem_cache *cachep, void *objp);

int destroy_cache(struct kmem_cache *cachep);