#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/vmalloc.h>
#include <linux/hdreg.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <cache_manager.h>

void *allocate_cache(struct kmem_cache *cachep, gfp_t flags){
  return kmem_cache_alloc(cachep, flags);
}

struct kmem_cache *create_cache(const char *name, size_t size, size_t align, unsigned long flags, void(*ctor)(void *)){
  struct kmem_cache * cache;
  cache = kmem_create_cache(name, size, align, flags, ctor);
  return cache;
}

void free_cache(struct kmem_cache *cachep, void *objp){
  kmem_cache_free(cachep, objp);
}

int destroy_cache(struct kmem_cache *cachep){
  return kmem_cache_destroy(cachep);
}