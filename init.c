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
    /* In the child */
    swapinit();
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