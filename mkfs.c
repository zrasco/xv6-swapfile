#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#define stat xv6_stat  // avoid clash with host struct stat
#include "types.h"
#include "fs.h"
#include "stat.h"
#include "param.h"

#ifndef static_assert
#define static_assert(a, b) do { switch (0) case 0: case (a): ; } while (0)
#endif

#define NINODES 200

// Disk layout:
// [ boot block | sb block | log | inode blocks | free bit map | data blocks ]

int nbitmap = FSSIZE/(BSIZE*8) + 1;
int ninodeblocks = NINODES / IPB + 1;
int nlog = LOGSIZE;
int nmeta;    // Number of meta blocks (boot, sb, nlog, inode, bitmap)
int nblocks;  // Number of data blocks

int fsfd;
struct superblock sb;
char zeroes[BSIZE];
uint freeinode = 1;
uint freeblock;


void balloc(int);
void wsect(uint, void*);
void winode(uint, struct dinode*);
void rinode(uint inum, struct dinode *ip);
void rsect(uint sec, void *buf);
uint ialloc(ushort type);
void iappend(uint inum, void *p, int n);

// convert to intel byte order
ushort
xshort(ushort x)
{
  ushort y;
  uchar *a = (uchar*)&y;
  a[0] = x;
  a[1] = x >> 8;
  return y;
}

uint
xint(uint x)
{
  uint y;
  uchar *a = (uchar*)&y;
  a[0] = x;
  a[1] = x >> 8;
  a[2] = x >> 16;
  a[3] = x >> 24;
  return y;
}

int
main(int argc, char *argv[])
{
  int i, cc, fd;
  uint rootino, inum, off;
  struct dirent de;
  char buf[BSIZE];
  struct dinode din;

  static_assert(sizeof(int) == 4, "Integers must be 4 bytes!");

  if(argc < 2){
    fprintf(stderr, "Usage: mkfs fs.img files...\n");
    exit(1);
  }

  assert((BSIZE % sizeof(struct dinode)) == 0);
  assert((BSIZE % sizeof(struct dirent)) == 0);

  fsfd = open(argv[1], O_RDWR|O_CREAT|O_TRUNC, 0666);
  if(fsfd < 0){
    perror(argv[1]);
    exit(1);
  }

  // 1 fs block = 1 disk sector
  nmeta = 2 + nlog + ninodeblocks + nbitmap;
  nblocks = FSSIZE - nmeta;

  sb.size = xint(FSSIZE);
  sb.nblocks = xint(nblocks);
  sb.ninodes = xint(NINODES);
  sb.nlog = xint(nlog);
  sb.logstart = xint(2);
  sb.inodestart = xint(2+nlog);
  sb.bmapstart = xint(2+nlog+ninodeblocks);

  printf("nmeta %d (boot, super, log blocks %u inode blocks %u, bitmap blocks %u) blocks %d total %d\n",
         nmeta, nlog, ninodeblocks, nbitmap, nblocks, FSSIZE);

  freeblock = nmeta;     // the first free block that we can allocate

  for(i = 0; i < FSSIZE; i++)
    wsect(i, zeroes);

  memset(buf, 0, sizeof(buf));
  memmove(buf, &sb, sizeof(sb));
  wsect(1, buf);

  rootino = ialloc(T_DIR);
  assert(rootino == ROOTINO);

  bzero(&de, sizeof(de));
  de.inum = xshort(rootino);
  strcpy(de.name, ".");
  iappend(rootino, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(rootino);
  strcpy(de.name, "..");
  iappend(rootino, &de, sizeof(de));

  for(i = 2; i < argc; i++){
    assert(index(argv[i], '/') == 0);

    if((fd = open(argv[i], 0)) < 0){
      perror(argv[i]);
      exit(1);
    }

    // Skip leading _ in name when writing to file system.
    // The binaries are named _rm, _cat, etc. to keep the
    // build operating system from trying to execute them
    // in place of system binaries like rm and cat.
    if(argv[i][0] == '_')
      ++argv[i];

    inum = ialloc(T_FILE);

    bzero(&de, sizeof(de));
    de.inum = xshort(inum);
    strncpy(de.name, argv[i], DIRSIZ);
    iappend(rootino, &de, sizeof(de));

    while((cc = read(fd, buf, sizeof(buf))) > 0)
      iappend(inum, buf, cc);

      /*
    if (i == 2)
    {
      
      uint indirect[NINDIRECT];
      uint dindirectindex[NDINDIRECT_ENTRY];
      uint dindirectdata[NDINDIRECT_PER_ENTRY];
      struct dinode din;
      rinode(inum, &din);
      printf("Done writing %s\n",argv[i]);

      
      // Print block table
      for (int x = 0; x < NDIRECT+2; x++)
      {
        printf("din.addr[%d]==%x\n",x,din.addrs[x]);

        if (x == NDIRECT)
        {
          // Indrect table read in
          rsect(din.addrs[x],(char*)indirect);

          for (int x1 = 0; x1 < NINDIRECT; x1++)
            printf("din.addr[%d][%d] aka indirect[%d]==%x\n",x,x1,x1,indirect[x1]);
        }
        else if (x == NDIRECT + 1)
        {
          dindirectdata[0] = dindirectdata[0];
          rsect(din.addrs[x],(char*)dindirectindex);
          
          for (int x1 = 0; x1 < NDINDIRECT_ENTRY; x1++)
          {
              printf("din.addr[%d][%d] aka dindirectindex[%d]==%x\n",x,x1,x1,dindirectindex[x1]);

              rsect(dindirectindex[x1],(char*)dindirectdata);

              for (int x2 = 0; x2 < NDINDIRECT_PER_ENTRY; x2++)
              {
                printf("din.addr[%d][%d][%d] aka dindirectdata[%d]==%x\n",x,x1,x2,x2,dindirectdata[x2]);
              }
          }

          //  printf("din.addr[%d][%d] aka dindirectindex[%d]==%x\n",x,)
        }
        
      }
      
    }
    */

    close(fd);
  }

  // fix size of root inode dir
  rinode(rootino, &din);
  off = xint(din.size);
  off = ((off/BSIZE) + 1) * BSIZE;
  din.size = xint(off);
  winode(rootino, &din);

  balloc(freeblock);

  exit(0);
}

void
wsect(uint sec, void *buf)
{
  if(lseek(fsfd, sec * BSIZE, 0) != sec * BSIZE){
    perror("lseek");
    exit(1);
  }
  if(write(fsfd, buf, BSIZE) != BSIZE){
    perror("write");
    exit(1);
  }
}

void
winode(uint inum, struct dinode *ip)
{
  char buf[BSIZE];
  uint bn;
  struct dinode *dip;

  bn = IBLOCK(inum, sb);
  rsect(bn, buf);
  dip = ((struct dinode*)buf) + (inum % IPB);
  *dip = *ip;
  wsect(bn, buf);
}

void
rinode(uint inum, struct dinode *ip)
{
  char buf[BSIZE];
  uint bn;
  struct dinode *dip;

  bn = IBLOCK(inum, sb);
  rsect(bn, buf);
  dip = ((struct dinode*)buf) + (inum % IPB);
  *ip = *dip;
}

void
rsect(uint sec, void *buf)
{
  if(lseek(fsfd, sec * BSIZE, 0) != sec * BSIZE){
    perror("lseek");
    exit(1);
  }
  if(read(fsfd, buf, BSIZE) != BSIZE){
    perror("read");
    exit(1);
  }
}

uint
ialloc(ushort type)
{
  uint inum = freeinode++;
  struct dinode din;

  bzero(&din, sizeof(din));
  din.type = xshort(type);
  din.nlink = xshort(1);
  din.size = xint(0);
  winode(inum, &din);
  return inum;
}

void
balloc(int used)
{
  uchar buf[BSIZE];
  int i;
  int bitmapblocks = (used / (BSIZE*8)) + 1;

  printf("balloc: first %d blocks have been allocated\n", used);
  printf("balloc: writing %d bitmap blocks\n", bitmapblocks);

  //assert(used < BSIZE*8);

  for (int x = 0; x < bitmapblocks; x++)
  {
    int used_begin = x * (BSIZE * 8);
    int used_end = (x + 1) * (BSIZE * 8);
    //printf("used_begin==%d, used_end==%d\n",used_begin,used_end);

    bzero(buf, BSIZE);
    for(i = used_begin; i < used_end; i++){
      int offset = (i - used_begin);
      printf("offset==%d\n",offset);
      buf[offset/8] = buf[offset/8] | (0x1 << (offset%8));
      //buf[i/8] = buf[i/8] | (0x1 << (i%8));
    }
    printf("balloc: write bitmap block #%d at sector %d\n", x + 1, sb.bmapstart + x);
    wsect((sb.bmapstart + x), buf);
  }

}

#define min(a, b) ((a) < (b) ? (a) : (b))

void
iappend(uint inum, void *xp, int n)
{
  char *p = (char*)xp;
  uint fbn, off, n1;
  struct dinode din;
  char buf[BSIZE];
  uint indirect[NINDIRECT];
  uint dindirectindex[NDINDIRECT_ENTRY];
  uint dindirectdata[NDINDIRECT_PER_ENTRY];
  uint x;

  rinode(inum, &din);
  off = xint(din.size);
  //printf("append inum %d at off %d sz %d\n", inum, off, n);
  while(n > 0){
    fbn = off / BSIZE;
    assert(fbn < MAXFILE);
    if (fbn < NDIRECT){
      // For addresses 1 thru NDIRECT (11)
      if(xint(din.addrs[fbn]) == 0){
        din.addrs[fbn] = xint(freeblock++);
      }
      x = xint(din.addrs[fbn]);
    }
    else if ((fbn - NDIRECT) < NINDIRECT) {
      int entry = fbn - NDIRECT;
      // For addresses NDIRECT thru NINDIRECT (128)
      if(xint(din.addrs[NDIRECT]) == 0){
        din.addrs[NDIRECT] = xint(freeblock++);
      }

      rsect(xint(din.addrs[NDIRECT]), (char*)indirect);

      if(indirect[entry] == 0){
        indirect[entry] = xint(freeblock++);
        wsect(xint(din.addrs[NDIRECT]), (char*)indirect);
      }
      x = xint(indirect[entry]);
    }
    else if ((fbn - NDIRECT) < NDOUBLE_INDIRECT)
    {
      int efbn = fbn - NDIRECT;     // effective fbn
      uint addr;
      int entry = (efbn - NINDIRECT) / NDINDIRECT_PER_ENTRY;
      int offset = (efbn - NINDIRECT) % NDINDIRECT_PER_ENTRY;

      // Base address of doubly indirect index table
      if(xint(din.addrs[NDIRECT + 1]) == 0){
        din.addrs[NDIRECT + 1] = addr = xint(freeblock++);
      }

      entry =  entry;
      offset = offset;
      dindirectindex[0] = 5;

      // Read the current index table into dindirectindex
      rsect(xint(din.addrs[NDIRECT + 1]), (char*)dindirectindex);

      if (dindirectindex[entry] == 0)
      {
        // Assign a block to this index entry
        dindirectindex[entry] = xint(freeblock++);
        wsect(xint(din.addrs[NDIRECT + 1]), (char*)dindirectindex);
      }

      // Read the current data block
      rsect(xint(dindirectindex[entry]), (char*)dindirectdata);

      if (dindirectdata[offset] == 0)
      {
        // Assign this data block
        dindirectdata[offset] = xint(freeblock++);
        wsect(xint(dindirectindex[entry]), (char*)dindirectdata);
      }
      
      x = xint(dindirectdata[offset]);
      }
    n1 = min(n, (fbn + 1) * BSIZE - off);
    rsect(x, buf);
    bcopy(p, buf + off - (fbn * BSIZE), n1);
    wsect(x, buf);
    n -= n1;
    off += n1;
    p += n1;
  }
  din.size = xint(off);
  winode(inum, &din);
}
