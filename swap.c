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

struct swap_info_struct swap_info;

void kswapinit()
{
  union swap_header *swap_header_local = (union swap_header*)kalloc();
  
  cprintf("Initializing swap file...\n");

  //cprintf("Address of swap header: %x. Size: %d\n",swap_header_ptr,sizeof(union swap_header));
  //cprintf("Address of swap info: %x. Size: %d\n",swap_info_ptr,sizeof(struct swap_info_struct));
  
  memset(&swap_info,0,sizeof(struct swap_info_struct));
  memset(swap_header_local,0,sizeof(union swap_header));

  // Set swap info fields

/*
  // Get # of pages in swapfile
  {
    int fd = 0;
    struct file *f;
    //struct stat st;
    struct inode *ip;

    //st = st;
    fd = fd;

    begin_op();
    
    if((ip = namei(SWAPFILE_FILENAME)) == 0)
      panic("Could not open swapfile!\n");
    else
    {
      cprintf("Size of swapfile: %d\n",ip->size);
    }      
    end_op();
    
    f = f;
  }
  */


  kfree((char*)swap_header_local);
  cprintf("Done initializing swap file.\n");
}

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