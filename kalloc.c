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
#include "swap.h"

void freerange(void *vstart, void *vend);
extern char end[]; // first address after kernel loaded from ELF file
                   // defined by the kernel linker script in kernel.ld

// Imported from swap.c
int swap_out(pte_t*, unsigned int);
swp_entry_t get_swap_page(void);

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
  kswapmem.total_pages = swap_page_total_count();

  // Set maximum process size. Do not allow sbrk() to exceed this
  kmem.max_proc_size = (kswapmem.total_pages + kmem.free_pages) * PGSIZE;

  cprintf("Max process memory size set to %dKB (%d physical pages, %d swap pages)\n",kmem.max_proc_size / 1024,kmem.free_pages,kswapmem.total_pages);

  kmem.use_lock = 1;
}

char *invoke_swapper()
// Swaps a page out and returns the free block of kernel memory for kalloc() to pass back
// Victim page is chosen via an LRU algorithm from one of the running processes. Kernel memory itself is not cannibalized for this purpose
// Assumes we can find a victim. If not, error checking will need to be added. Haven't run into this yet, however.
{
  //cprintf("Out of physical memory and invoking swapper [%s]. eip==0x%p, fault_addr==0x%p, fault_page==0x%p\n",
  //            currproc->name,tf->eip,fault_addr,fault_page);
  // Out of physical memory, so invoke the swapper.
  // Physical memory page range is anywhere from the 4MB kernel boundary to PHYSTOP (0x80400000 to 0x81000000, for example)
  // uva2ka(currproc->pgdir, process virtual address as char* )

  // Can't do anything with no swap pages available!
  if (swap_page_count() == 0)
  {
    cprintf("kalloc: no swap pages left!\n");
    return NULL;
  }
    
  
  // 1) Choose a victim page via the LRU algorithm
  unsigned int proc_addr = 0;
  
  pde_t *victim_pde = (pde_t*)get_victim_page(&proc_addr);
  pte_t *mapped_victim_pte = (pte_t*)victim_pde;
  pte_t new_victim_pte = 0;
  char *kernel_addr = P2V(PTE_ADDR(*mapped_victim_pte));

  //cprintf("Victim addr: 0x%p\n",victim_pde);
  //cprintf("Victim page chosen! process addr==0x%p, kernel addr==0x%p\n", proc_addr, kernel_addr);
  //cprintf("pte=0x%p\n",victim);
  //cprintf("victim pte location=0x%p\nPTE flags: PTE_P=%d,PTE_U=%d,PTE_W=%d,PTE_D=%d\n",
  //        victim_pde,*victim_pde & PTE_P,*victim_pde & PTE_U, *victim_pde & PTE_W,*victim_pde & PTE_D);
        
  // The process page table entry for this page should be at a unique address in kernel memory above the KERNBASE + 4MB line
  // This gives us a unique offset to the swap map, which is shared amongst all processes
  
  //char *kaddr_of_victim = uva2ka(currproc->victim,)

  //swp_entry_t swap_slot = pte_to_swp_entry((uint)victim_pde);
  swp_entry_t new_slot = get_swap_page();
  //cprintf("Got new swap slot. Slot #%d. Swap pages left: %d\n",SWP_OFFSET(new_slot),swap_page_count());
  
  //cprintf("Writing contents of page to %s at position %d\n",SWAPFILE_FILENAME,PGSIZE * (SWP_OFFSET(new_slot) + 1));
  //cprintf("Swap map offset of this PTE: %d\n",SWP_OFFSET(swap_slot));
  swap_out(victim_pde, SWP_OFFSET(new_slot));
  //cprintf("Done writing contents. swap_val==%d\n",swap_val);
  
  cprintf("kernel: Page 0x%p(ka: 0x%p) in a process swapped out to slot %d.\n",proc_addr,kernel_addr,SWP_OFFSET(new_slot));
  // PTE no longer resident or dirty
  new_victim_pte = swp_entry_to_pte(new_slot);
  new_victim_pte |= PTE_FLAGS(*mapped_victim_pte);
  new_victim_pte &= ~PTE_P;
  new_victim_pte &= ~PTE_D;

  // Replace the PTE
  *mapped_victim_pte = new_victim_pte;

  //*mapped_victim_pte = swp_entry_to_pte(new_slot);

  //cprintf("victim pte location=0x%p\nPTE flags: PTE_P=%d,PTE_U=%d,PTE_W=%d,PTE_D=%d\n",
  //        victim_pde,*victim_pde & PTE_P,*victim_pde & PTE_U, *victim_pde & PTE_W,*victim_pde & PTE_D);          

  //cprintf("new victim pte offset: %d, flags: PTE_P=%d,PTE_U=%d,PTE_W=%d,PTE_D=%d\n", SWP_OFFSET(new_slot),
  //        new_victim_pte & PTE_P,new_victim_pte & PTE_U,new_victim_pte & PTE_W,new_victim_pte & PTE_D);

  
  //swap_slot = swap_slot;
  
  // 2) If the victim is non-dirty and is already mapped to a slot in the swap file, do nothing.
  // 2a) If the victim is dirty and is already mapped to a slot in the swap file, write that page to the swap file & clear dirty bit.

  // 2b) If the victim is not mapped to a slot in the swap file, get a free slot & map it.
  //     If none available, out of memory error and terminate process
  // 2c) Otherwise, write that page to the swap file & clear dirty bit.

  // 3) At this point we have a viable victim page, with the contents in the swapfile. Mark that page as non-present


  // 4) Call mappages OR
  // 4) Use kfree() on the associated address
  return kernel_addr;
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

  if (r == NULL)
    // Out of physical memory. Invoke swapper. If the swapper returns NULL, we're completely out of memory!
    r = (struct run*)invoke_swapper();
  
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