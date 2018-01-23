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

// In full linux, these are variables and defined in include/linux/mmzone.h
// For the sake of simplicity, we'll define them here instead.
#define PAGES_LOW 100
#define PAGES_HIGH 1000

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

/*
unsigned int swap_page_count()
{
  unsigned int total_pages;
  int fd;
  struct stat st;

  // Determine number of swapfile pages

  if ((fd = open("SWAPFILE", 0)) < 0) {
    cprintf("No swapfile!\n");
    return (uint)-1;
  }
  else
  {
    if(fstat(fd, &st) < 0){
      cprintf("Cannot fstat swapfile!\n");
      return (uint)-1;
    }
    else
    {
      total_pages = st.size / 4096;
    }
  }
  close(fd);

  return total_pages;
}*/