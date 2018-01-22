#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "spinlock.h"

// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

// Imported from vm.c for lazy allocation
int mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm);
pte_t *walkpgdir(pde_t *pgdir, const void *va, int alloc);

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);

  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}

//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }
  else if (tf->trapno == T_ILLOP && tf->err == 0)
  // This happens when doing a NULL-reference in user mode
  {
    cprintf("Segmentation fault from instruction address 0x%p accessing address 0x%p. Terminating program!\n",tf->eip,rcr2());
    myproc()->killed = 1;
    exit();
  }

  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;
  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpuid(), tf->cs, tf->eip);
    lapiceoi();
    break;
  case T_PGFLT:
    if (myproc() == 0)
    // No page faults should happen in kernel mode
      panic("trap");
    else
    {
      struct proc *currproc = myproc();
      char *mem;
      unsigned int fault_addr = rcr2();
      unsigned int fault_page = PGROUNDDOWN(fault_addr);

      // Page fault occured in user space, likely from lazy allocation
      //cprintf("Page fault from process [%s]. Faulting addr: 0x%p. Faulting page: 0x%p\n",
      //  myproc()->name,fault_addr,fault_page);

      currproc->page_fault_cnt++;

      // Get page table entry associated with faulting address
      pte_t *pte = walkpgdir(currproc->pgdir,(const void*)fault_addr,0);
      //cprintf("pte=0x%p, *pte=0x%p\n",pte,*pte);

      // In user space, assume process misbehaved.
      //cprintf("pid %d %s: trap %d err %d on cpu %d "
      //        "eip 0x%x addr 0x%x--kill proc\n",
      //        currproc->pid, currproc->name, tf->trapno, tf->err, cpuid(), tf->eip,
      //        rcr2());
      //currproc->killed = 1;

      // Check for segfault (access violation)
      // Occurs if:
      // 1) Faulting address happens outside process boundary
      //    - Obviously this includes anything kernel-related, which starts at 0x80000000
      // 2) PTE is non-NULL, present, and user access is not allowed (i.e. user stack guard page)
      //
      // TODO: Still iffy about this logic, test some more!
      if (fault_addr > currproc->sz || (pte != NULL && ((*pte & PTE_P) && !(*pte & PTE_U))))
      {
        cprintf("Segmentation fault from instruction address 0x%p accessing address 0x%p. Terminating program!\n",tf->eip,fault_addr);
        if (pte != NULL)
          *pte |= PTE_U;

        // Enable for debug purposes
        //cprintf("pgtabinfo() debug output:\n");
        //pgtabinfo();

        currproc->killed = 1;
        break;
      }
      else if (pte == NULL || !(*pte & PTE_P))
      {
        // Get a new page of memory (borrowed from allocuvm())

        // TODO: Figure out why kalloc() is called twice. Once here, then once in mappages()
        // This is probably OK but I'm tired!
        mem = kalloc();

        if (mem == NULL)
        {
          currproc->killed = 1;
          cprintf("Lazy allocation(1) failed at address 0x%p. Terminating process [%s].\n",
            fault_page,currproc->name);
        }
        else
        {
          //memset(mem, 0, PGSIZE);

          //cprintf("mappages(0x%x,0x%x,%d,0x%x,PTE_W|PTE_U\n",currproc->pgdir,(char*)fault_addr,PGSIZE,V2P(mem));

          if(mappages(currproc->pgdir, (char*)fault_page, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0) {
            cprintf("Lazy allocation(2) failed at address 0x%p. Terminating process [%s].\n",
              fault_page,currproc->name);
            //deallocuvm(pgdir, newsz, oldsz);
            kfree(mem);
            currproc->killed = 1;
          }
          else
          {
            //cprintf("Page of size %d bytes allocated for process [%s] at virtual address 0x%p for physical address 0x%p\n",
            //  PGSIZE,currproc->name,fault_page,V2P(mem));

            // Increase count of pages "actually" allocated
            currproc->phys_sz += PGSIZE;

            /*
            if (currproc->phys_sz > currproc->sz)
            {
              cprintf("phys_sz greater than sz. phys_sz=0x%p, sz=0x%p\n",currproc->phys_sz,currproc->sz);
              cprintf("walkpgdir result for rounded down sz(0x%p): 0x%p\n",
                PGROUNDDOWN(currproc->sz),walkpgdir(currproc->pgdir,(const void*)PGROUNDDOWN(currproc->sz),0));
              cprintf("walkpgdir result for rounded up sz(0x%p): 0x%p\n",
                PGROUNDUP(currproc->sz),walkpgdir(currproc->pgdir,(const void*)PGROUNDUP(currproc->sz),0));

              cprintf("walkpgdir result for rounded up sz + 4096*5000(0x%p): 0x%p\n",
                PGROUNDUP(currproc->sz) + PGSIZE*5000,walkpgdir(currproc->pgdir,(const void*)(PGROUNDUP(currproc->sz) + PGSIZE*5000),0));


              cprintf("walkpgdir result for 0x0B000000: 0x%p\n",walkpgdir(currproc->pgdir,(const void*)(PGROUNDUP(184579376)),0));
            }
            */

            return;
          }        
        }
      }
      else
      {
        cprintf("Unknown page fault type. pte=0x%p\nPTE flags: PTE_P=%d,PTE_U=%d\n",pte,*pte & PTE_P,*pte & PTE_U);
        currproc->killed = 1;
      }
    }
    break;

  //PAGEBREAK: 13
  default:
    if(myproc() == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpuid(), tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            myproc()->pid, myproc()->name, tf->trapno, tf->err, cpuid(), tf->eip,
            rcr2());
    myproc()->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running
  // until it gets to the regular system call return.)
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING && tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();
}
