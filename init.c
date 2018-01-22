// init: The initial user-level program

#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"
#include "spinlock.h"
#include "mmu.h"
#include "swap.h"

char *argv[] = { "sh", 0 };

int
main(void)
{
  int pid, pid_s, wpid;

  if(open("console", O_RDWR) < 0){
    mknod("console", 1, 1);
    open("console", O_RDWR);
  }
  dup(0);  // stdout
  dup(0);  // stderr

  printf(1, "init: initializing swap space\n");
  pid_s = fork();

  if(pid_s < 0){
    printf(1, "init: fork failed\n");
    exit();
  }
  else if (pid_s == 0)
  {
    int fd;
    union swap_header *hdr = (union swap_header*)malloc(sizeof(union swap_header));
    /* In the child */
    printf(1, "init (swap): initializing swap space\n");

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

      close(fd);
      printf(1, "init (swap): swap file closed\n");

    }
    printf(1, "init (swap): done initializing swap space\n");
    free(hdr);
    exit();
  }
  else
  {
    /* In parent. Wait for swapfile to initialize */
    wait();

    for(;;){
      printf(1, "init: starting sh\n");
      pid = fork();
      if(pid < 0){
        printf(1, "init: fork failed\n");
        exit();
      }
      if(pid == 0){
        exec("sh", argv);
        printf(1, "init: exec sh failed\n");
        exit();
      }
      while((wpid=wait()) >= 0 && wpid != pid)
        printf(1, "zombie!\n");
    }
  }


}
