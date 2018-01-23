// User-mode swap API
#include "types.h"
#include "user.h"
#include "spinlock.h"
#include "mmu.h"
#include "fcntl.h"
#include "swap.h"

// User-mode methods for swap file

void swapinit()
{
  int fd = 0;
  union swap_header *hdr = (union swap_header*)malloc(sizeof(union swap_header));
  printf(1, "init (swap): initializing swap space\n");

  // Will remain open while OS is running
  fd = open(SWAPFILE_FILENAME,O_RDWR);

  if (fd < 0)
  {
    printf(1, "init (swap): unable to open swap file\n");
  }
  else
  {
    printf(1, "init (swap): swap file opened\n");

    memset(hdr, 0 ,sizeof(union swap_header));
    strcpy(hdr->magic.magic,"SWAP-FILE");

    printf(1, "init (swap): writing swap file header\n");
    write(fd,hdr,sizeof(union swap_header));

    // System call for setting swapfile
    setswapfilefd(fd);

    close(fd);
    printf(1, "init (swap): swap file closed\n");
  }
  
  printf(1, "init (swap): done initializing swap space\n");
  free(hdr);
  close(fd);
}