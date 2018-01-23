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

#define SWAPFILE_CLUSTER 16

void kswapd()
{
  int free_pages = kfreepagecnt1();

  if (free_pages < PAGES_LOW)
  {
    // Invoke the swapper. Will mark (PAGES_HIGH - PAGES_LOW) pages to be swapped
  }
}

unsigned int swap_page_count()
{
  // TODO: Use swapfile mechanism to get actual # of pages
  return SWAPFILE_PAGES;
  //return swap_info_ptr->pages;
  //return 65536 / 4096;
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
			offset = scan_swap_map(p);
			swap_device_unlock(p);
			if (offset) {
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
  cprintf("Swap file pointer set!\n");
  swap_info[0].swap_file = f;
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
			if (si->swap_map[offset])
				continue;
			si->cluster_nr--;
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
		swap_info[0].pages--;
		si->cluster_next = offset+1;
		return offset;
	}
	si->lowest_bit = si->max;
	si->highest_bit = 0;
	return 0;
}