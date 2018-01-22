// Physical memory allocator, intended to allocate
// memory for user processes, kernel stacks, page table pages,
// and pipe buffers. Allocates 4096-byte pages.

#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "spinlock.h"
#include "stat.h"

void freerange(void *vstart, void *vend);
extern char end[]; // first address after kernel loaded from ELF file
                   // defined by the kernel linker script in kernel.ld

struct run {
  struct run *next;
};

struct {
  struct spinlock lock;
  int use_lock;
  struct run *freelist;

  uint allocated_pages;                     // # of pages not on freelist
  uint free_pages;                          // # of pages on freelist
  uint kernel_data_boundary;
  uint max_proc_size;
} kmem;

struct {
  struct spinlock lock;
  int use_lock;
  struct run *freelist;

  // Set during kinit2. Equal to (Size of swapfile / page size)
  unsigned int total_pages;

} kswapmem;

// Initialization happens in two phases.
// 1. main() calls kinit1() while still using entrypgdir to place just
// the pages mapped by entrypgdir on free list.
// 2. main() calls kinit2() with the rest of the physical pages
// after installing a full page table that maps them on all cores.
void
kinit1(void *vstart, void *vend)
{
  initlock(&kmem.lock, "kmem");
  kmem.use_lock = 0;
  kmem.kernel_data_boundary = PGROUNDUP((uint)vstart);
  freerange(vstart, vend);
}

void
kinit2(void *vstart, void *vend)
{
  freerange(vstart, vend);
  kmem.allocated_pages = 0;
  kmem.free_pages = kfreepagecnt();
  kswapmem.total_pages = swap_page_count();

  // Set maximum process size. Do not allow sbrk() to exceed this
  kmem.max_proc_size = (kswapmem.total_pages + kmem.free_pages) * PGSIZE;

  cprintf("Max process memory size set to %dKB\n",kmem.max_proc_size / 1024);

  kmem.use_lock = 1;
}

void
freerange(void *vstart, void *vend)
{
  char *p;

  cprintf("Free pages before: %d\n",kfreepagecnt());

  p = (char*)PGROUNDUP((uint)vstart);
  
  cprintf("Calling freerange. vstart=0x%p(0x%p) [rounded to 0x%p], vend=0x%p(0x%p)\n",
    vstart,V2P(vstart),p,vend,V2P(vend));

  for(; p + PGSIZE <= (char*)vend; p += PGSIZE)
    kfree(p);

  cprintf("Free pages after: %d\n",kfreepagecnt());

}

//PAGEBREAK: 21
// Free the page of physical memory pointed at by v,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(char *v)
{
  struct run *r;

  if((uint)v % PGSIZE || v < end || V2P(v) >= PHYSTOP)
    panic("kfree");

  // Fill with junk to catch dangling refs.
  memset(v, 1, PGSIZE);

  if(kmem.use_lock)
    acquire(&kmem.lock);
  r = (struct run*)v;
  r->next = kmem.freelist;
  kmem.freelist = r;
  kmem.allocated_pages--;
  kmem.free_pages++;
  if(kmem.use_lock)
    release(&kmem.lock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
char*
kalloc(void)
{
  struct run *r;

  if(kmem.use_lock)
    acquire(&kmem.lock);
  r = kmem.freelist;
  if(r)
  {
    kmem.freelist = r->next;
    kmem.allocated_pages++;
    kmem.free_pages--;
  }

  if(kmem.use_lock)
    release(&kmem.lock);
  return (char*)r;
}

inline uint kmaxprocsize()
// No process can grow beyond this size
// Equal to (# physical + # swap pages) * PGSIZE
{
  return kmem.max_proc_size;
}

inline int kexistfreepages()
// Quick function to check for free kernel pages. Used in sbrk()
// Returns 1 if freelist has entries, 0 if not
{
  return (kmem.freelist != NULL);
}

unsigned int kfreepagecnt()
{
  unsigned int retval = 0;
  struct run *r;

  // Get the number of nodes on kmem.freelist (# of physical pages)
  if (kmem.use_lock)
    acquire(&kmem.lock);
  r = kmem.freelist;

  while (r)
  {
    retval++;
    r = r->next;
  }

  if(kmem.use_lock)
    release(&kmem.lock);

  return retval;
}

inline unsigned int kfreepagecnt1()
{
  return kmem.free_pages;
}

inline uint kallocatedpages()
{
  return kmem.allocated_pages;
}

inline uint kallocbeginning()
{
  return kmem.kernel_data_boundary;
}

inline struct run *kgetfreelistptr()
{
  return kmem.freelist;
}