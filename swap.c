// Kernel-mode swap API
#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"
#include "swap.h"
#include "stat.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"

// In full linux, these are variables and defined in include/linux/mmzone.h
// For the sake of simplicity, we'll define them here instead.
#define PAGES_LOW 100
#define PAGES_HIGH 1000

// Type will always be 0, but other types may also be added
struct swap_info_struct swap_info[1];
struct spinlock swaplock;

// Forward declarations
swp_entry_t get_swap_page(void);
int scan_swap_map(struct swap_info_struct*);
void lru_list_initialize();
void lru_cache_del(pte_t, uint);

#define SWAPFILE_CLUSTER 16
//#define SWAPFILE_CLUSTER 3

void kswapinit()
{
	unsigned int swapmap_bytes_needed = SWAPFILE_PAGES * sizeof(unsigned short);
	cprintf("kernel: Initializing swap info\n");

	memset(&swap_info[0],0,sizeof(struct swap_info_struct));
	swap_info[0].pages = swap_info[0].max = SWAPFILE_PAGES;
	swap_info[0].max--;
	swap_info[0].swap_map_pages = 1 + (swapmap_bytes_needed / PGSIZE);
	swap_info[0].flags = SWP_WRITEOK;
	swap_info[0].highest_bit = SWAPFILE_PAGES - 1;
	swap_info[0].cluster_nr = SWAPFILE_CLUSTER;

	initlock(&swaplock,"swaplock");
	initlock(&swap_info[0].sdev_lock,"sdev_lock");

	cprintf("kernel: swapmap bytes needed: %d\n",swapmap_bytes_needed);
	cprintf("kernel: swapmap pages needed: %d\n",swap_info[0].swap_map_pages);

	for (int x = 0; x < swap_info[0].swap_map_pages; x++)
	{
		// IMPORTANT NOTE:
		// We assume here that kalloc'ed pages will happen in a sequence from high to low. This method should be executed early enough
		// in xv6 initialization, so this should happen every time. Hence we can do a strightforward implementation.
		//
		// Example scenario:
		// 4 pages needed for the swap map total, so 4 passes thru the loop
		// 1st page allocated at 0x804FF000
		// 2nd page allocated at 0x804FE000
		// 3rd page allocated at 0x804FD000
		// 4th page allocated at 0x804FC000. Swap map pointer set to 0x804FC000 since this is the last page.
		//
		// In this case we have the range for the swap map allocated from 0x804FC000 to 0x804FFFFF for a total of 16k

		char *new_kalloc_page = kalloc();
		memset(new_kalloc_page,0,PGSIZE);
		cprintf("kernel: Allocating page for swap map at address 0x%p\n",new_kalloc_page);
		
		if (x == swap_info[0].swap_map_pages - 1)
		{
			// Allocate & zero out this section of the map
			swap_info[0].swap_map = (unsigned short*)new_kalloc_page;

			cprintf("kernel: Swap map pointer set to address 0x%p\n",new_kalloc_page);
		}
	}

	lru_list_initialize();
	
	cprintf("kernel: Done initializing swap info\n");
}

void print_swap_map()
{
	cprintf("Swap map(lb==%d, hb==%d):\n",swap_info[0].lowest_bit,swap_info[0].highest_bit);

	for (int x = 0; x < SWAPFILE_PAGES; x++)
		cprintf("%d ",swap_info[0].swap_map[x]);

	cprintf("\n");
}

void kswapd()
{
  int free_pages = kfreepagecnt1();

  if (free_pages < PAGES_LOW)
  {
    // Invoke the swapper. Will mark (PAGES_HIGH - PAGES_LOW) pages to be swapped
  }
}

unsigned int swap_page_total_count()
{
	return SWAPFILE_PAGES;
}

unsigned int swap_page_count()
{
  return swap_info[0].pages;
}

inline unsigned int swap_refcount(unsigned long offset)
{
	if (offset > SWAPFILE_PAGES)
		panic("swap_refcount");

	return swap_info[0].swap_map[offset];
}

int swap_duplicate(swp_entry_t entry)
{
	unsigned int offset = SWP_OFFSET(entry);

	if (offset > SWAPFILE_PAGES)
		panic("swap_duplicate");
	
	swap_list_lock();
	++swap_info[0].swap_map[offset];	
	swap_list_unlock();

	return swap_info[0].swap_map[offset];
}

int swap_entry_free(struct swap_info_struct *p, unsigned long offset)
{
	int count = p->swap_map[offset];

	if (count < SWAP_MAP_MAX) {
		count--;
		p->swap_map[offset] = count;
		if (!count) {
			if (offset < p->lowest_bit)
				p->lowest_bit = offset;
			if (offset > p->highest_bit)
				p->highest_bit = offset;
			p->pages++;
			//cprintf("swap slot %d freed. # of swap pages: %d\n",offset,p->pages);
		}
	}
	return count;
}

int swap_free(swp_entry_t entry)
{
	int retval = 0;
	struct swap_info_struct * p = &swap_info[0];

	swap_list_lock();
	retval = swap_entry_free(p, SWP_OFFSET(entry));
	swap_list_unlock();

	return retval;
}

int swap_free_nolocks(swp_entry_t entry)
// WARNING: Make sure to protect this call with locks!
{
	return swap_entry_free(&swap_info[0], SWP_OFFSET(entry));
}

unsigned int *get_victim_page(unsigned int *proc_addr)
// Returns the address of a page directory entry for the next victim page
{
  // Not yet implemented. Uses LRU with all processes in the system (kernel memory is all considered non-swappable)
  struct proc *currproc = myproc();

  // For now, just get first present page available from the process that needs a victim page

  // Below is stolen from pgtabinfo_internal. Ignore the first 10 pages to prevent thrasing w/code execution (code will keep being paged out & back in)

  for (int index1 = 0; index1 < NPDENTRIES; index1++)
  // Page tables have two tiers. Traverse tier 1, the page directory
  {
    // Check which of the 1024 page directory entries, or PDEs, are present (512 are user-space).
    // Each PDE contains info for up to 1024 page table entries, or PTEs. This is equal to a 4MB range per PDE.
    //
    // So with each PDE being able to address 4MB, and 1024 PDEs, this gives the entire 32-bit range or 4GB.
    pde_t *pde = &(currproc->pgdir[index1]);

    if (*pde & PTE_P && index1 < 512)
    // Page directory
    {
      // Now traverse through second tier, the page table corresponding to the page directory entry above
      // This page table is full of PTEs, each of which can address 4KB
      pde_t *pgtab = (pte_t*)P2V(PTE_ADDR(*pde));

      for (int index2 = 11; index2 < NPTENTRIES; index2++)
      {
        if (pgtab[index2] & PTE_P)
        {
          *proc_addr = (unsigned int)PGADDR(index1,index2,0);
          return (unsigned int*)&pgtab[index2];
        }
          
      }
    }
  }

  return 0;
}

void free_swap_pages(struct proc *currproc)
// Frees all swap pages 
{
  //print_swap_map();
  swap_list_lock();

  // Standard page directory crawl
  for (int index1 = 0; index1 < NPDENTRIES; index1++)
  {
    pde_t *pde = &(currproc->pgdir[index1]);

    if (*pde & PTE_P && index1 < 512)
    {
      pde_t *pgtab = (pte_t*)P2V(PTE_ADDR(*pde));

	  lru_cache_del((uint)pgtab,PGSIZE);
	  cprintf("kernel: proc exit crawl. pgtab addr: 0x%p\n",pgtab);

      for (int index2 = 11; index2 < NPTENTRIES; index2++)
      {
        if (!(pgtab[index2] & PTE_P) && (pgtab[index2] & PTE_U))
        {
			// Check if this page is swapped out
			swp_entry_t this_entry = pte_to_swp_entry(pgtab[index2]);
			uint offset = SWP_OFFSET(this_entry);

			if (offset < SWAPFILE_PAGES && swap_info[0].swap_map[offset] != 0)
			{
				cprintf("process [%s] exiting. freeing slot entry %d. New refcount==%d\n",currproc->name,offset,swap_free_nolocks(this_entry));
			}
        }
      }
    }
  }

  swap_list_unlock();
}

int swap_out(pte_t *mapped_victim_pte, unsigned int offset)
// My own method (basically add_to_swap_cache() without the cache)
{
	struct swap_info_struct *p = &swap_info[0];
	int file_offset = offset + 1, retval = -1;
	uint old_offset;
	char *kernel_addr = P2V(PTE_ADDR(*mapped_victim_pte));

	if (p->swap_file == NULL)
	// SWAPFILE pointer not set yet with ksetswapfileptr() system call
		return -1;

	//cprintf("Writing page located at 0x%p to file with file pointer at address 0x%p from bytes %d to %d\n",
	//					kernel_addr,p->swap_file,(file_offset * PGSIZE), (file_offset * PGSIZE) + PGSIZE);

	old_offset = p->swap_file->off;
	
	/*
	cprintf("Before list lock\n");
	swap_list_lock();
	cprintf("Before device lock\n");
	swap_device_lock(p);
	*/

	// Quick and dirty hack for now. Need a lock-protected state variable later
	myproc()->pages_swapped_out++;

	// Write contents to swapfile
	p->swap_file->off = (unsigned int)(file_offset * PGSIZE);
  	retval = filewrite(p->swap_file,kernel_addr,PGSIZE);
  	p->swap_file->off = old_offset;

	/*
	cprintf("Before dev unlock\n");
	swap_device_unlock(p);
	cprintf("Before list unlock\n");
	swap_list_unlock();
	*/

	return retval;
}

int swap_in(void *page_addr, unsigned int offset)
// My own method. Swap a page into main memory from the specified slot
{
	struct swap_info_struct *p = &swap_info[0];
	int file_offset = offset + 1, retval = -1;
	uint old_offset;

	if (p->swap_file == NULL)
	// SWAPFILE pointer not set yet with ksetswapfileptr() system call
		return -1;

	old_offset = p->swap_file->off;

	// Quick and dirty hack for now. Need a lock-protected state variable later
	myproc()->pages_swapped_out--;

	// Read contents from swapfile
	p->swap_file->off = (unsigned int)(file_offset * PGSIZE);
  retval = fileread(p->swap_file,page_addr,PGSIZE);
  p->swap_file->off = old_offset;

	return retval;
}

/* From linux 2.4 source code w/modifications */
swp_entry_t get_swap_page()
{
	struct swap_info_struct * p;
	unsigned long offset;
	swp_entry_t entry;
	int type;

	entry.val = 0;	/* Out of memory */
	swap_list_lock();
	type = 0;
	if (type < 0)
		goto out;
	if (swap_info[0].pages <= 0)
		goto out;

	while (1) {
		p = &swap_info[type];
		if ((p->flags & SWP_WRITEOK) == SWP_WRITEOK) {
			swap_device_lock(p);
			//cprintf("before scan_swap_map\n");
			offset = scan_swap_map(p);
			//cprintf("after scan_swap_map. offset==%d\n",offset);
			
			swap_device_unlock(p);
			if (offset >= 0) {
				entry = SWP_ENTRY(type,offset);

        /* Don't need the type stuff below\
				type = swap_info[type].next;
				if (type < 0 ||
					p->prio != swap_info[type].prio) {
						swap_list.next = swap_list.head;
				} else {
					swap_list.next = type;
				}
        */
				goto out;
			}
		}
    /*
		type = p->next;
		if (!wrapped) {
			if (type < 0 || p->prio != swap_info[type].prio) {
				type = swap_list.head;
				wrapped = 1;
			}
		} else
			if (type < 0)
				goto out;	// out of swap space
      */
	}
out:
	swap_list_unlock();
	return entry;
}

inline void ksetswapfileptr(struct file *f)
{
  cprintf("kernel: Swap file pointer set! Address of file pointer: 0x%p\n",f);
	//cprintf("kernel: inode ptr: 0x%p\n",f->ip);
	//cprintf("kernel: offset: 0x%p\n",f->off);
  swap_info[0].swap_file = filedup(f);
}

inline int scan_swap_map(struct swap_info_struct *si)
{
	unsigned long offset;
	/* 
	 * We try to cluster swap pages by allocating them
	 * sequentially in swap.  Once we've allocated
	 * SWAPFILE_CLUSTER pages this way, however, we resort to
	 * first-free allocation, starting a new cluster.  This
	 * prevents us from scattering swap pages all over the entire
	 * swap partition, so that we reduce overall disk seek times
	 * between swap pages.  -- sct */
	if (si->cluster_nr) {
		while (si->cluster_next <= si->highest_bit) {
			offset = si->cluster_next++;
			//cprintf("in first if. si->cluster_next==%d, si->highest_bit==%d\n",si->cluster_next,si->highest_bit);
			if (si->swap_map[offset])
				continue;
			si->cluster_nr--;
			//cprintf("in first if. offset==%d\n",offset);
			goto got_page;
		}
	}
	si->cluster_nr = SWAPFILE_CLUSTER;

	/* try to find an empty (even not aligned) cluster. */
	offset = si->lowest_bit;
 check_next_cluster:
	if (offset+SWAPFILE_CLUSTER-1 <= si->highest_bit)
	{
		int nr;
		for (nr = offset; nr < offset+SWAPFILE_CLUSTER; nr++)
			if (si->swap_map[nr])
			{
				offset = nr+1;
				goto check_next_cluster;
			}
		/* We found a completly empty cluster, so start
		 * using it.
		 */
		//cprintf("in second if. offset==%d\n",offset);
		goto got_page;
	}
	/* No luck, so now go finegrined as usual. -Andrea */
	for (offset = si->lowest_bit; offset <= si->highest_bit ; offset++) {
		if (si->swap_map[offset])
			continue;
		si->lowest_bit = offset+1;
	got_page:
		if (offset == si->lowest_bit)
			si->lowest_bit++;
		if (offset == si->highest_bit)
			si->highest_bit--;
		if (si->lowest_bit > si->highest_bit) {
			si->lowest_bit = si->max;
			si->highest_bit = 0;
		}
		si->swap_map[offset] = 1;
		si->pages--;
		si->cluster_next = offset+1;
		return offset;
	}
	si->lowest_bit = si->max;
	si->highest_bit = 0;
	return 0;
}

// LRU section
struct lru_list_entry {
	pte_t addr;
	struct lru_list_entry *next;
};

struct lru_list_struct {
	struct lru_list_entry *active_list;
	struct lru_list_entry *inactive_list;
};

// Note that we can have a large number of entries in the LRU list, which may overflow the kernel stack.
// As a result, we need a subsystem to manage the doling out of LRU entries to be used, which we will dub the LRU bank

// Needed to figure out how many pages to allocate for LRU list bank
// Assume 12 bytes for header (prev & next pointers and count)
#define LRU_HEADER_SIZE 12
#define LRU_ENTRIES_PER_PAGE ((PGSIZE - LRU_HEADER_SIZE) / sizeof(struct lru_list_entry))

struct lru_bank_page {
	// Contains blocks of LRU entries to be given out when needed
	struct lru_bank_page *prev;
	struct lru_bank_page *next;
	unsigned int used;

	struct lru_list_entry slots[LRU_ENTRIES_PER_PAGE];
};

// Main container for LRU lists
struct lru_list_struct lru_list;
struct lru_bank_page *lru_bank = NULL;

void lru_list_initialize()
{
	cprintf("kernel: Initializing LRU list container.\n");

	lru_bank = (struct lru_bank_page*)kalloc();

	if (!lru_bank)
		panic("Unable to allocate LRU bank!");
	
	memset(lru_bank,0,sizeof(struct lru_bank_page));

	cprintf("kernel: First page of LRU entry bank created at 0x%p\n", lru_bank);

	cprintf("kernel: Initializing LRU active & inactive lists\n", lru_bank);
	lru_list.active_list = NULL;
	lru_list.inactive_list = NULL;

	cprintf("kernel: LRU entries per page: %d\n", LRU_ENTRIES_PER_PAGE);
}

struct lru_bank_page *lru_bank_current()
{
	struct lru_bank_page *retval = lru_bank;

	//cprintf("kernel: lru_bank_current(), lru_bank==0x%p\n",lru_bank);

	while (retval->next)
		retval = retval->next;

	//cprintf("kernel: lru_bank_current(), returning 0x%p\n",retval);

	return retval;
}

struct lru_list_entry *lru_bank_get_new()
// Returns a fresh LRU entry to be used
{
	struct lru_list_entry *retval = NULL;
	struct lru_bank_page *lb_curr = lru_bank_current();
	struct lru_bank_page *lb_last = NULL;

	//cprintf("kernel: lru_bank_get_new(): Before while loop\n");
	//cprintf("kernel: lru_bank_get_new(): lb_curr==0x%p\n",lb_curr);
	//cprintf("kernel: lru_bank_get_new(): lb_curr->next==0x%p\n",lb_curr->next);

	while (lb_curr)
	{
		uint exit = 0;

		if (lb_curr->used < LRU_ENTRIES_PER_PAGE)
		{
			// Take an entry from the current page
			for (int x = 0; x < LRU_ENTRIES_PER_PAGE; x++)
			{
				if (lb_curr->slots[x].addr == 0)
				// Found free entry
					retval = &lb_curr->slots[x];
					lb_curr->used++;
					exit = 1;
					break;
			}
		}

		if (exit > 0)
			break;

		// No free entries found. Try next page
		lb_last = lb_curr;
		lb_curr = lb_curr->next;
	}

	//cprintf("kernel: lru_bank_get_new(): After while loop\n");

	if (retval == NULL)
	// All LRU entries in all currently allocated bank pages are in use. Create a new bank page
	{
		if (lb_last == NULL)
			panic("lru_bank_get_new(): lb_last != NULL assertion failed");

		// Create new bank page
		lb_curr = lb_last->next = (struct lru_bank_page*)kalloc();
		lb_curr->prev = lb_last;
		memset(lb_curr,0,PGSIZE);

		// Assign new LRU item
		retval = &lb_curr->slots[0];
		lb_curr->used++;
	}

	cprintf("kernel: Got new LRU entry at address 0x%p\n",&retval);

	retval->addr = 0;
	retval->next = NULL;
	return retval;
}

struct lru_bank_page *lru_bank_find_page(struct lru_list_entry *entry)
// Finds the LRU bank page of the associated entry. Should never return NULL
{
	struct lru_bank_page *retval = NULL;
	struct lru_bank_page *currpg = lru_bank;

	while (currpg && retval == NULL)
	{
		if ((uint)entry >= (uint)currpg && (uint)entry < (uint)currpg + PGSIZE)
			retval = currpg;

		currpg = currpg->next;
	}

	return retval;
}

void lru_bank_release(struct lru_list_entry *target)
// Removes target entry from the LRU bank
{
	struct lru_bank_page *currpg = lru_bank_find_page(target);
	
	if (currpg == NULL)
		panic("lru_bank_release()");
	
	// Blank out this LRU entry and free it for use
	target->addr = 0;
	currpg->used--;
}

void lru_cache_add(pte_t addr, int pageHot)
// Add a cold page to the inactive_list. Will be moved to active_list with a call to mark_page_accessed()
// if the page is known to be hot, such as when a page is faulted in (pageHot > 0).
{
	struct lru_list_entry *new_entry = lru_bank_get_new();
	struct lru_list_entry *curr;

	cprintf("kernel: lru_cache_add(): new_entry==0x%p\n",new_entry);

	if (pageHot <= 0)
	{
		// Page isn't known to be hot. Move to end of inactive list
		curr = lru_list.inactive_list;

		// Add entry to end of inactive list
		if (lru_list.inactive_list == NULL)
			lru_list.inactive_list = new_entry;
		else
		{
			while (curr->next)
				curr = curr->next;

			curr->next = new_entry;
		}

		new_entry->addr = addr;
	}
	else
	{
		// Since we know the page is hot, put it in the front of the active list right now
		new_entry->addr = addr;		
		new_entry->next = lru_list.active_list;
		lru_list.active_list = new_entry;
	}

}
void lru_cache_del(pte_t addr, uint rangeSize)
// Removes a page from the LRU lists by calling either del_page_from_active_list()
// or del_page_from_inactive_list(), whichever is appropriate.
// The parameter rangeSize deletes all addresses between (addr) and (addr + rangeSize). Set rangeSize to 0 to specify a single address
{
	// Search active list...
	struct lru_list_entry *curr = lru_list.active_list;
	struct lru_list_entry *prev = curr;

	if (curr != NULL)
	{
		// Check if the first entry is the target
		if (curr->addr >= addr && curr->addr <= (addr + rangeSize))
		{
			lru_list.active_list = curr->next;
			cprintf("kernel: Removing LRU entry from active list for PTE at kernel address 0x%p\n",curr->addr);
			lru_bank_release(curr);
			
			if (rangeSize == 0)
				return;
		}

		// Remove entry from the list
		while (curr->next)
		{
			prev = curr;
			curr = curr->next;			

			if (curr->addr >= addr && curr->addr <= (addr + rangeSize))
			{
				prev->next = curr->next;
				cprintf("kernel: Removing LRU entry from active list for PTE at kernel address 0x%p\n",curr->addr);
				lru_bank_release(curr);
				curr = prev->next;

				if (rangeSize == 0)
					return;
			}
		}
	}

	// Search inactive list...
	curr = lru_list.inactive_list;
	prev = curr;

	if (curr != NULL)
	{
		// Check if the first entry is the target
		if (curr->addr >= addr && curr->addr <= (addr + rangeSize))
		{
			lru_list.active_list = curr->next;
			cprintf("kernel: Removing LRU entry from inactive list for PTE at kernel address 0x%p\n",curr->addr);
			lru_bank_release(curr);

			if (rangeSize == 0)
				return;
		}

		// Remove entry from the list
		while (curr->next)
		{
			prev = curr;
			curr = curr->next;

			if (curr->addr >= addr && curr->addr <= (addr + rangeSize))
			{
				prev->next = curr->next;
				cprintf("kernel: Removing LRU entry from inactive list for PTE at kernel address 0x%p\n",curr->addr);
				lru_bank_release(curr);
				curr = prev->next;

				if (rangeSize == 0)
					return;
			}
		}
	}	
}

void mark_page_accessed(pte_t addr)
// Mark that the page has been accessed. If it was not recently referenced
// (in the inactive_list and PG_referenced flag not set), the referenced flag is set.
// If it is referenced a second time, activate_page() is called, which marks the page hot, and the referenced flag is cleared
{


}
void activate_page(pte_t addr)
// Removes a page from the inactive_list and places it on active_list. 
// It is very rarely called directly as the caller has to know the page is on inactive_list. mark_page_accessed() should be used instead
{

}