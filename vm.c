#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"
#include "spinlock.h"
#include "swap.h"

extern char data[];  // defined by kernel.ld
pde_t *kpgdir;  // for use in scheduler()


// swap.c
int swap_duplicate(swp_entry_t);
int swap_free(swp_entry_t);

// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void
seginit(void)
{
  struct cpu *c;

  // Map "logical" addresses to virtual addresses using identity map.
  // Cannot share a CODE descriptor for both kernel and user
  // because it would have to have DPL_USR, but the CPU forbids
  // an interrupt from CPL=0 to DPL=3.
  c = &cpus[cpuid()];
  c->gdt[SEG_KCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, 0);
  c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
  c->gdt[SEG_UCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, DPL_USER);
  c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);
  lgdt(c->gdt, sizeof(c->gdt));
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    //cprintf("walkpgdir(): pgtab created at 0x%p\n",pgtab);
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;

  a = (char*)PGROUNDDOWN((uint)va);
  last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
  for(;;){
    if((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if(*pte & PTE_P)
    {
      //cprintf("va=0x%p,size=%d,pa=0x%p\n",va,size,pa);
      panic("remap");
    }
    *pte = pa | perm | PTE_P;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
//
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP,
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap {
  void *virt;
  uint phys_start;
  uint phys_end;
  int perm;
} kmap[] = {
 { (void*)KERNBASE, 0,             EXTMEM,    PTE_W}, // I/O space
 { (void*)KERNLINK, V2P(KERNLINK), V2P(data), 0},     // kern text+rodata
 { (void*)data,     V2P(data),     PHYSTOP,   PTE_W}, // kern data+memory
 { (void*)DEVSPACE, DEVSPACE,      0,         PTE_W}, // more devices
};

// Set up kernel part of a page table.
pde_t*
setupkvm(void)
{
  pde_t *pgdir;
  struct kmap *k;

  if((pgdir = (pde_t*)kalloc()) == 0)
    return 0;
  memset(pgdir, 0, PGSIZE);
  if (P2V(PHYSTOP) > (void*)DEVSPACE)
    panic("PHYSTOP too high");
  for(k = kmap; k < &kmap[NELEM(kmap)]; k++)
    if(mappages(pgdir, k->virt, k->phys_end - k->phys_start,
                (uint)k->phys_start, k->perm) < 0) {
      freevm(pgdir);
      return 0;
    }
  return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void
kvmalloc(void)
{
  kpgdir = setupkvm();
  cprintf("setupkvm() allocated kpgdir. &kpgdir=0x%p(0x%p), kpgdir=0x%p(0x%p)\n",&kpgdir,V2P(&kpgdir),
    kpgdir,V2P(kpgdir));
  switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void
switchkvm(void)
{
  lcr3(V2P(kpgdir));   // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void
switchuvm(struct proc *p)
{
  if(p == 0)
    panic("switchuvm: no process");
  if(p->kstack == 0)
    panic("switchuvm: no kstack");
  if(p->pgdir == 0)
    panic("switchuvm: no pgdir");

  pushcli();
  mycpu()->gdt[SEG_TSS] = SEG16(STS_T32A, &mycpu()->ts, sizeof(mycpu()->ts)-1, 0);
  mycpu()->gdt[SEG_TSS].s = 0;
  mycpu()->ts.ss0 = SEG_KDATA << 3;
  mycpu()->ts.esp0 = (uint)p->kstack + KSTACKSIZE;
  // setting IOPL=0 in eflags *and* iomb beyond the tss segment limit
  // forbids I/O instructions (e.g., inb and outb) from user space
  mycpu()->ts.iomb = (ushort) 0xFFFF;
  ltr(SEG_TSS << 3);
  lcr3(V2P(p->pgdir));  // switch to process's address space
  popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void
inituvm(pde_t *pgdir, char *init, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pgdir, 0, PGSIZE, V2P(mem), PTE_W|PTE_U);
  memmove(mem, init, sz);
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int
loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
  uint i, pa, n;
  pte_t *pte;

  if((uint) addr % PGSIZE != 0)
    panic("loaduvm: addr must be page aligned");
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, addr+i, 0)) == 0)
      panic("loaduvm: address should exist");
    pa = PTE_ADDR(*pte);
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, P2V(pa), offset+i, n) != n)
      return -1;
  }
  return 0;
}

// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int
allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  char *mem;
  uint a;

  if(newsz >= KERNBASE)
    return 0;
  if(newsz < oldsz)
    return oldsz;

  a = PGROUNDUP(oldsz);
  for(; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      cprintf("allocuvm out of memory\n");
      deallocuvm(pgdir, newsz, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    //cprintf("mappages(0x%x,0x%x,%d,0x%x,PTE_W|PTE_U\n",pgdir,(char*)a,PGSIZE,V2P(mem));
    if(mappages(pgdir, (char*)a, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0){
      cprintf("allocuvm out of memory (2)\n");
      deallocuvm(pgdir, newsz, oldsz);
      kfree(mem);
      return 0;
    }
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int
deallocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  pte_t *pte;
  uint a, pa;

  if(newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  for(; a  < oldsz; a += PGSIZE){
    pte = walkpgdir(pgdir, (char*)a, 0);
    if(!pte)
      a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
    else if((*pte & PTE_P) != 0){
      pa = PTE_ADDR(*pte);
      if(pa == 0)
        panic("kfree");
      char *v = P2V(pa);
      kfree(v);
      *pte = 0;
    }
  }
  return newsz;
}

// Free a page table and all the physical memory pages
// in the user part.
void
freevm(pde_t *pgdir)
{
  uint i;

  if(pgdir == 0)
    panic("freevm: no pgdir");
  deallocuvm(pgdir, KERNBASE, 0);
  for(i = 0; i < NPDENTRIES; i++){
    if(pgdir[i] & PTE_P){
      char * v = P2V(PTE_ADDR(pgdir[i]));
      kfree(v);
    }
  }
  kfree((char*)pgdir);
}

// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void
clearpteu(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if(pte == 0)
    panic("clearpteu");
  *pte &= ~PTE_U;
}

// Given a parent process's page table, create a copy
// of it for a child.
pde_t*
copyuvm(pde_t *pgdir, uint sz)
{
  pde_t *d;
  pte_t *pte;
  uint pa, i, flags;
  char *mem;

  if((d = setupkvm()) == 0)
    return 0;

  //cprintf("copyuvm: sz==%d\n",sz);
  for(i = 0; i < sz; i += PGSIZE){

    if((pte = walkpgdir(pgdir, (void *) i, 0)) == 0)
      panic("copyuvm: pte should exist");

    //cprintf("pte #%d location=0x%p\nPTE flags: PTE_P=%d,PTE_U=%d,PTE_W=%d,PTE_D=%d\n", i / PGSIZE,
    //        pte,*pte & PTE_P,*pte & PTE_U, *pte & PTE_W,*pte & PTE_D);

    // The pages within the process boundary not being present isn't an issue since we have lazy allocation and swapping
    // Instead, we'll only kalloc() if the page is present
    //
    //if(!(*pte & PTE_P))
    //  panic("copyuvm: page not present");

    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);

    if (*pte & PTE_P)
    {
      // Only copy pages if present. If the page is swapped, increment the reference counter
      if((mem = kalloc()) == 0)
        goto bad;
      memmove(mem, (char*)P2V(pa), PGSIZE);
      if(mappages(d, (void*)i, PGSIZE, V2P(mem), flags) < 0)
        goto bad;
    }
    else
    {
      // Check for swapped page. If we have one, increment the reference counter
      if (*pte & PTE_U)
      {
        // Possibly have an access request to a swapped-out page
        swp_entry_t entry = pte_to_swp_entry(*pte);
        uint offset = SWP_OFFSET(entry);
        uint refcount = swap_refcount(offset);

          if (refcount > 0)
          {
            refcount = swap_duplicate(entry);
            //cprintf("copyuvm: copying swapped page in process address 0x%p, slot %d. new ref count: %d\n",i,offset,refcount);

            // Very likely this page is swapped out. Copy the PTE to the new process
            if(mappages(d, (void*)i, PGSIZE, offset, flags) < 0)
              goto bad;
            else
            {
              pte_t *newpte = walkpgdir(d,(void*)i,0);
              //cprintf("copyuvm: mappages() succeeded in swap branch. Adjusting page table entry\n");

              // The old PTE is exactly what we need so just copy it
              *newpte = *pte;
            }
          }
      }
    }
  }
  return d;

bad:
  freevm(d);
  return 0;
}

//PAGEBREAK!
// Map user virtual address to kernel address.
char*
uva2ka(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if((*pte & PTE_P) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  return (char*)P2V(PTE_ADDR(*pte));
}

// Copy len bytes from p to user address va in page table pgdir.
// Most useful when pgdir is not the current page table.
// uva2ka ensures this only works for PTE_U pages.
int
copyout(pde_t *pgdir, uint va, void *p, uint len)
{
  char *buf, *pa0;
  uint n, va0;

  buf = (char*)p;
  while(len > 0){
    va0 = (uint)PGROUNDDOWN(va);
    pa0 = uva2ka(pgdir, (char*)va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (va - va0);
    if(n > len)
      n = len;
    memmove(pa0 + (va - va0), buf, n);
    len -= n;
    buf += n;
    va = va0 + PGSIZE;
  }
  return 0;
}

struct run {
  struct run *next;
};

void print_lru();

int vminfo_internal(struct vminfo_struct *vminfo_container)
// Syscall which provides the user with memory information via a container structure vminfo_struct
{
  struct run *r = kgetfreelistptr();
  int count = 0;

  // Initialize the container
  memset(vminfo_container,0,sizeof(struct vminfo_struct));

  // General virtual memory info
  vminfo_container->physical_pages_free = kfreepagecnt();
  vminfo_container->physical_pages_allocated = kallocatedpages();
  vminfo_container->kernel_data_lower_boundary = KERNLINK;
  vminfo_container->kernel_data_upper_boundary = kallocbeginning();
  vminfo_container->kernel_data_pages = 
    (vminfo_container->kernel_data_upper_boundary - vminfo_container->kernel_data_lower_boundary) / PGSIZE;
  vminfo_container->physical_pages_total = vminfo_container->kernel_data_pages +
                                            vminfo_container->physical_pages_allocated +
                                            vminfo_container->physical_pages_free;
  vminfo_container->page_size = PGSIZE;

  // Freelist info
  vminfo_container->kernel_mem_freelist_first = (uint)r;

  while (r)
  {
    if (!(r->next))
      vminfo_container->kernel_mem_freelist_last = (uint)r;
    r = r->next;
    count++;
  }

  // Process info
  procsmemorystats(vminfo_container);

  print_lru();
  lru_rotate_lists();
  print_lru();
  lru_rotate_lists();
  print_lru();

  return 0;
}

int pgtabinfo_internal(void)
// Syscall that prints out the page table for the calling process, including kernel page table
// Code borrowed from various other parts including walkpgdir()
{
  struct proc *currproc = myproc();
  uint upgdircount = 0;             // User present page directory entry count
  uint kpgdircount = 0;             // Kernel present page directory entry count
  uint uphyspages = 0;              // User physical pages allocated
  uint kphyspages = 0;              // Kernel physical pages allocated (entire kernel)

  cprintf("Address of page table for process [%s] is 0x%p\n",currproc->name,currproc->pgdir);
  cprintf("Process upper-bound address is 0x%p\n",currproc->sz);
  cprintf("Last page inside process is 0x%p\n",PGROUNDDOWN(currproc->sz));

  for (int index1 = 0; index1 < NPDENTRIES; index1++)
  // Page tables have two tiers. Traverse tier 1, the page directory
  {
    // Check which of the 1024 page directory entries, or PDEs, are present (512 are user-space).
    // Each PDE contains info for up to 1024 page table entries, or PTEs. This is equal to a 4MB range per PDE.
    //
    // So with each PDE being able to address 4MB, and 1024 PDEs, this gives the entire 32-bit range or 4GB.
    pde_t *pde = &(currproc->pgdir[index1]);

    if (*pde & PTE_P)
    // Page directory
    {
      if (index1 < 512)
        // User page
        upgdircount++;
      else
        kpgdircount++;

      // Now traverse through second tier, the page table corresponding to the page directory entry above
      // This page table is full of PTEs, each of which can address 4KB
      pde_t *pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
      uint pgtabentries = 0;
      uint user_accessible = 0;

      for (int index2 = 0; index2 < NPTENTRIES; index2++)
      {
        if (pgtab[index2] & PTE_P)
        {
          pgtabentries++;

          if (pgtab[index2] & PTE_U)
            user_accessible++;

          // Inefficient but straightforward. Should be optimized via CPU pipelining anyway
          if (index1 < 512)
            uphyspages++;
          else
            kphyspages++;
        }

        if (index1 < 512 && index2 < 20)
        {
          cprintf("PTE #%d(at addr 0x%p): va: 0x%p. Flags: PTE_U=%d PTE_P=%d,PTE_W=%d,PTE_D=%d,PTE_A=%d\n",
          index2,&pgtab[index2],PGADDR(index1,index2,0),pgtab[index2] & PTE_U,
            pgtab[index2] & PTE_P, pgtab[index2] & PTE_W, pgtab[index2] & PTE_D, pgtab[index2] & PTE_A);

          if (pgtab[index2] & PTE_P)
            cprintf("PTE #%d: points to address: 0x%p\n",index2,PTE_ADDR(pgtab[index2]));
          else if (pgtab[index2] & PTE_U)
          {
            // Check if this is a swapped out page
            swp_entry_t entry = pte_to_swp_entry(pgtab[index2]);
            uint offset = SWP_OFFSET(entry);
            uint refcount = swap_refcount(offset);

            if (refcount > 0)
              // Very likely this is a swapped out page
              cprintf("PTE #%d: swapped out to slot %d, ref count: %d\n",index2,offset,refcount);
          }
        }
      }

      // TODO: Figure out which pages are requested but not yet allocated to physical memory (lazy allocation)
      if (index1 < 512)
        cprintf("PDE #%d: va: 0x%p. PTEs present: %d. PTE_U itself: %d. PTE_U cnt: %d\n",
        index1,PGADDR(index1,0,0),pgtabentries,*pde & PTE_U,user_accessible);
    }
  }

  cprintf("Total process pages requested/size: %d/%dKB\n",
    PGROUNDUP(currproc->sz) / PGSIZE,PGROUNDUP(currproc->sz) / 1024);
  cprintf("User page directory entries: %d. Kernel page directory entries: %d\n",upgdircount,kpgdircount);
  cprintf("Total %d byte pages of physical memory allocated(user): %d\n",PGSIZE,uphyspages);
  cprintf("Total %d byte pages of physical memory allocated(kernel): %d\n",PGSIZE,kphyspages);


/*
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page tablef
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
*/
  return 0;
}

//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.