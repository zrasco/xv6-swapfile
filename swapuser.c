#include "types.h"
#include "user.h"
#include "spinlock.h"
#include "mmu.h"
#include "fcntl.h"
#include "swap.h"

// User-mode methods for swap file

struct swap_info_struct swap_info;

void swapinit()
{
  union swap_header *hdr = (union swap_header*)malloc(sizeof(union swap_header));
  printf(1, "init (swap): initializing swap space\n");

  memset(&swap_info,0,sizeof(swap_info));
  swap_info.pages = SWAPFILE_PAGES;

  // Will remain open while OS is running
  swap_info.fd = open(SWAPFILE_FILENAME,O_RDWR);

  if (swap_info.fd < 0)
  {
    printf(1, "init (swap): unable to open swap file\n");
  }
  else
  {
    printf(1, "init (swap): swap file opened (%d pages)\n",swap_info.pages);

    memset(hdr, 0 ,sizeof(union swap_header));
    strcpy(hdr->magic.magic,"SWAP-FILE");

    printf(1, "init (swap): writing swap file header\n");
    write(swap_info.fd,hdr,sizeof(union swap_header));

    //close(swap_info.fd);
    printf(1, "init (swap): swap file closed\n");
  }
  
  printf(1, "init (swap): done initializing swap space\n");
  free(hdr);
}