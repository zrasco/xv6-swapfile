#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  //else if (!kexistfreepages())
  //  return -1;

  addr = myproc()->sz;

  if (addr > kmaxprocsize())
  // No need to pretend we can allocate anything beyond this. The calling process would never be able to actually
  // use all of this memory due to a lack of physical + swap pages.
    return -1;

  if (n > 0)
    // Increases the "requested pages" count. Physical pages incremented during lazy allocation
    myproc()->sz += n;
  else
  {
    if (growproc(n) < 0)
      return -1;
  } 

  // Call removed to implement lazy allocation
  //if(growproc(n) < 0)
  //  return -1;

  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

// Return virtual memory information
int sys_vminfo(void)
{
  struct vminfo_struct *vminfo_container;

  if(argptr(0, (char**)&vminfo_container,sizeof(vminfo_container)) < 0)
    return -1;

  return vminfo_internal(vminfo_container);
}

// Return page table info for a given process
int sys_pgtabinfo(void)
{
  return pgtabinfo_internal();
}