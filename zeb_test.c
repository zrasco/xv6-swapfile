#include "types.h"
#include "stat.h"
#include "user.h"
#include "memlayout.h"				// For sbrktest

#define stdout 1

// Forward declarations
void read_blocks();
void sbrktest(void);
void mem(void);
void vminfo_printstats(struct vminfo_struct*);

// A simple atoi() function
// Source: http://www.geeksforgeeks.org/write-your-own-atoi/
int myAtoi(char *str)
{
    int res = 0; // Initialize result
  
    // Iterate through all characters of input string and
    // update result
    for (int i = 0; str[i] != '\0'; ++i)
        res = res*10 + str[i] - '0';
  
    // return result.
    return res;
}

int main(int argc, char *argv [])
{
  char *victim_addr = (char*)0x0000C008;
  char *alloc_addr = NULL;
  alloc_addr = alloc_addr;
  //char ch;
  printf(1,"Target victim addr: 0x%p\n",victim_addr);

  /*
  ch = 5;
  ch = ch;
  printf(1,"Before malloc\n");
  
  printf(1,"Malloc returned 0x%p\n",alloc_addr);
  
  printf(1,"Before read attempt\n");
  ch = *alloc_addr;
  printf(1,"After read attempt\n");

  printf(1,"Before write attempt\n");
  *alloc_addr = 'x';
  printf(1,"After write attempt\n");

  printf(1,"Before write attempt 2\n");
  *alloc_addr = 'x';
  printf(1,"After write attempt 2\n");

  exit();
  */

	//struct vminfo_struct *myvminfo = malloc(sizeof(struct vminfo_struct));

	//vminfo(myvminfo);

	//vminfo_printstats(myvminfo);
  
	//printf(1,"Free swap pages: %d\n",myvminfo->swap_pages_free);

  for (int x = 0; x < 1000000; x++)
  {
    // Malloc header is 8 bytes, so entire allocated block takes up exactly one page
    // Hence alloc_addr will always fall on a page boundary + 8 (ex. 0x0000A008)
    printf(1,"Allocating a page...");
    char *alloc_addr = malloc(4096-8);

    if (x == 15)
    {
      *victim_addr = 'Y';
      pgtabinfo();
    }
      
    else if (x == 939)
    {
      // Our pet victim page should be swapped out by now
      printf(1,"\nReading from victim area");
      char ch = *victim_addr;

      ch = ch * 1;
      printf(1,"\nDone reading from victim area. Value==%d\n",ch);
    }
    if (alloc_addr == NULL)
      break;
    else
      printf(1,"page #%d: malloc returned 0x%p\n",x + 1,alloc_addr);

    //char ch = *alloc_addr;
    //ch = ch * 1;

    //printf(1,"x==%d\n",x);
  }
	exit();

	//read_blocks();
	//mem();
	//malloc(4096); // 5
	
	//malloc(4096); // 6
	//malloc(4096); // 7
	//malloc(4096); // 8
	//malloc(4096); // 9
	//malloc(4096); // 10
	//malloc(4096); // 10 (but should be 11)
	

	/*
	printf(1,"vminfo() before!\n");
	vminfo();
	char *addr[10];

	for (int x = 0; x < 10; x++)
	{
		addr[x] = malloc(1024*1024*2);
		//malloc(1024*1024*2);
		//memset(addr[x],0,1024*1024*2);
	}

	printf(1,"\nvminfo() after allocating 4KB!\n\n");
	vminfo();


	printf(1,"Done. Memsetting!\n");

	for (int x = 0; x < 10; x++)
	{
		memset(addr[x],0,1024*1024*2);
	}

	printf(1,"\nvminfo() after memsetting the 4KB!\n\n");

	
	vminfo();

	*/

	char *blockaddr[500];

	/*
	char *kernbase = (char*)0x71000000;
	char *kernpage = malloc(4096);

	memset(kernpage,0,4096);

	printf(1,"Copying 4096 bytes from 0x71000000 to user memory...");
	memmove(kernpage,kernbase,4096);
	printf(1,"done!\n");
	*/


	//memset(kernbase,0,1024*1024*10);

	if (argc > 1)
	{
		int allocBlocks = myAtoi(argv[1]);
		int allocBlocksOrig = allocBlocks;

		if (allocBlocks > 0)
			printf(1,"Allocating %d blocks...\n",allocBlocks);

		for (int x = 0; x < allocBlocks; x++)
		{
			blockaddr[x] = malloc(1024*1024);

			if (blockaddr[x] == NULL)
				
			{
				printf(1,"Unable to allocate any more memory! Total 1MB blocks allocated: %d\n",x);
				allocBlocks = x;
				break;
			}
			//else
				//printf(1,"Allocating 1MB block #%d at 0x%p\n",x + 1, blockaddr[x]);
		}

		if (allocBlocks == allocBlocksOrig)
			printf(1,"All %d blocks allocated!\n",allocBlocks);

		printf(1,"\n*** Page table info before memset ***\n");
		//pgtabinfo();

		for (int x = 0; x < allocBlocks; x++)
			memset(blockaddr[x],0,1024*1024);

		printf(1,"\n*** Page table info after memset ***\n");
		//pgtabinfo();		

	}
	else
		printf(1,"Missing parameter of # of blocks to allocate. Terminating...\n");

	// Read those blocks!
	//read_blocks();

	exit();
}


void read_blocks()
{
	char *blockrdr = (char*)0x00002000;
	
	const int BYTE_SIZE = 500;
	char storage[BYTE_SIZE];

	//printf(1,"&read_blocks=0x%p,&blockrdr=0x%p,&BYTE_SIZE=0x%p,&storage=0x%p\n",&read_blocks,(char*)&blockrdr,(char*)&BYTE_SIZE,(char*)&storage);
	//exit();
	
	printf(1,"\nReading %p byte blocks starting at address 0x%p! Working",BYTE_SIZE,blockrdr);
	
	while (blockrdr < (char*)0x80000000)
	// Dont go into kernel space
	{
		memmove(&storage,blockrdr,BYTE_SIZE);
		printf(1,".");
		blockrdr += BYTE_SIZE;
	}
	

}

void sbrktest(void)
{
  int fds[2], pid, pids[10], ppid;
  char *a, *b, *c, *lastaddr, *oldbrk, *p, scratch;
  uint amt;

  printf(stdout, "sbrk test\n");
  oldbrk = sbrk(0);

  // can one sbrk() less than a page?
  a = sbrk(0);
  int i;
  for(i = 0; i < 5000; i++){
    b = sbrk(1);
    if(b != a){
      printf(stdout, "sbrk test failed %d %x %x\n", i, a, b);
      exit();
    }
    *b = 1;
    a = b + 1;
  }
  pid = fork();
  if(pid < 0){
    printf(stdout, "sbrk test fork failed\n");
    exit();
  }
  c = sbrk(1);
  c = sbrk(1);
  if(c != a + 1){
    printf(stdout, "sbrk test failed post-fork\n");
    exit();
  }
  if(pid == 0)
    exit();
  wait();

  // can one grow address space to something big?
#define BIG (100*1024*1024)
  a = sbrk(0);
  amt = (BIG) - (uint)a;
  p = sbrk(amt);
  if (p != a) {
    printf(stdout, "sbrk test failed to grow big address space; enough phys mem?\n");
    exit();
  }
  lastaddr = (char*) (BIG-1);
  *lastaddr = 99;

  // can one de-allocate?
  a = sbrk(0);
  c = sbrk(-4096);
  if(c == (char*)0xffffffff){
    printf(stdout, "sbrk could not deallocate\n");
    exit();
  }
  c = sbrk(0);
  if(c != a - 4096){
    printf(stdout, "sbrk deallocation produced wrong address, a %x c %x\n", a, c);
    exit();
  }

  // can one re-allocate that page?
  a = sbrk(0);
  c = sbrk(4096);
  if(c != a || sbrk(0) != a + 4096){
    printf(stdout, "sbrk re-allocation failed, a %x c %x\n", a, c);
    exit();
  }
  if(*lastaddr == 99){
    // should be zero
    printf(stdout, "sbrk de-allocation didn't really deallocate\n");
    exit();
  }

  a = sbrk(0);
  c = sbrk(-(sbrk(0) - oldbrk));
  if(c != a){
    printf(stdout, "sbrk downsize failed, a %x c %x\n", a, c);
    exit();
  }

  // can we read the kernel's memory?
  for(a = (char*)(KERNBASE); a < (char*) (KERNBASE+2000000); a += 50000){
    ppid = getpid();
    pid = fork();
    if(pid < 0){
      printf(stdout, "fork failed\n");
      exit();
    }
    if(pid == 0){
      printf(stdout, "oops could read %x = %x\n", a, *a);
      kill(ppid);
      exit();
    }
    wait();
  }

  // if we run the system out of memory, does it clean up the last
  // failed allocation?
  if(pipe(fds) != 0){
    printf(1, "pipe() failed\n");
    exit();
  }
  for(i = 0; i < sizeof(pids)/sizeof(pids[0]); i++){
    if((pids[i] = fork()) == 0){
      // allocate a lot of memory
      sbrk(BIG - (uint)sbrk(0));
      write(fds[1], "x", 1);
      // sit around until killed
      for(;;) sleep(1000);
    }
    if(pids[i] != -1)
      read(fds[0], &scratch, 1);
  }
  // if those failed allocations freed up the pages they did allocate,
  // we'll be able to allocate here
  c = sbrk(4096);
  for(i = 0; i < sizeof(pids)/sizeof(pids[0]); i++){
    if(pids[i] == -1)
      continue;
    kill(pids[i]);
    wait();
  }
  if(c == (char*)0xffffffff){
    printf(stdout, "failed sbrk leaked memory\n");
    exit();
  }

  if(sbrk(0) > oldbrk)
    sbrk(-(sbrk(0) - oldbrk));

  printf(stdout, "sbrk test OK\n");
}

void
mem(void)
{
  void *m1, *m2;
  int pid, ppid;

  printf(1, "mem test\n");
  ppid = getpid();
  if((pid = fork()) == 0){
    m1 = 0;
    while((m2 = malloc(10001)) != 0){
    	//printf(1, "successful m2 malloc at 0x%p. Size=%dKB\n",m2,(uint)m2 / 1024);
      *(char**)m2 = m1;
      m1 = m2;
    }
    while(m1){
      m2 = *(char**)m1;
      free(m1);
      m1 = m2;
    }
    m1 = malloc(1024*20);
    if(m1 == 0){
      printf(1, "couldn't allocate mem?!!\n");
      kill(ppid);
      exit();
    }
    else
    	printf(1, "successful m1 malloc at 0x%p. Size=%dKB\n",m1,(uint)m1 / 1024);
    free(m1);
    printf(1, "mem ok\n");
    exit();
  } else {
    wait();
  }
}

void vminfo_printstats(struct vminfo_struct *vminfo_container)
{
  unsigned const int PAGE_SIZE = vminfo_container->page_size;
  unsigned const int KBSIZE = 1024;
  unsigned const int MBSIZE = 1024*1024;
  uint totalprocsize = 0;

  printf(1,"Total physical pages: %d\n",
  	vminfo_container->physical_pages_total);

  printf(1,"Free physical pages: %d\n",vminfo_container->physical_pages_free);
  printf(1,"Allocated physical pages: %d\n",vminfo_container->physical_pages_allocated);
  
  printf(1,"Kernel data/text: %d pages(%dKB) [0x%p-0x%p]\n",
    vminfo_container->kernel_data_pages,
    (vminfo_container->kernel_data_upper_boundary - vminfo_container->kernel_data_lower_boundary) / PAGE_SIZE,
    vminfo_container->kernel_data_lower_boundary,
    vminfo_container->kernel_data_upper_boundary);

  printf(1,"Free physical memory (approx): %dKB(%dMB)\n",
  	(vminfo_container->physical_pages_free * PAGE_SIZE) / KBSIZE,
  	(vminfo_container->physical_pages_free * PAGE_SIZE) / MBSIZE);

  printf(1,"Total number of swap pages: %d\n",vminfo_container->swap_pages_total);
  printf(1,"Free swap pages: %d\n",vminfo_container->swap_pages_total);

  printf(1,"Freelist 1st: 0x%p(0x%p)\n",vminfo_container->kernel_mem_freelist_first,
  										V2P(vminfo_container->kernel_mem_freelist_first));

  printf(1,"Freelist last: 0x%p(0x%p)\n",vminfo_container->kernel_mem_freelist_last,
  										V2P(vminfo_container->kernel_mem_freelist_last));

  printf(1,"\n---------- Processes ----------\n");

  for (int i = 0; i < vminfo_container->proc_count; i++)
  {
    printf(1,"Pages requested/allocated for process [%s]: %d(%dKB or %dMB)/%d(%dKB or %dMB)\n",
    	vminfo_container->proclist[i],
      vminfo_container->procsizes[i] / PAGE_SIZE,
      vminfo_container->procsizes[i] / KBSIZE,
      vminfo_container->procsizes[i] / MBSIZE,
      vminfo_container->procphyssizes[i] / PAGE_SIZE,
      vminfo_container->procphyssizes[i] / KBSIZE,
      vminfo_container->procphyssizes[i] / MBSIZE);

    totalprocsize += vminfo_container->procsizes[i];
    printf(1,"Page faults: %d\n",vminfo_container->procpagefaultcnts[i]);
  }

  printf(1,"\nTotal pages allocated for %d processes: %d(%dKB or %dMB)\n",
    vminfo_container->proc_count,
    totalprocsize / PAGE_SIZE,
    totalprocsize / KBSIZE,
    totalprocsize / MBSIZE);
}