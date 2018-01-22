typedef unsigned int   uint;
typedef unsigned short ushort;
typedef unsigned char  uchar;
typedef uint pde_t;

// Seems like a good place to put this...
#ifndef NULL
#define NULL ((void*)0)
#endif

// Common structures used for passing info between kernel & user mode, so they must be the same.

struct vminfo_struct {
	// Memory statistics
  	uint physical_pages_total;
  	uint physical_pages_allocated;
  	uint physical_pages_free;
  	uint kernel_data_pages;
  	uint kernel_data_lower_boundary;
  	uint kernel_data_upper_boundary;
  	uint kernel_mem_freelist_first;
  	uint kernel_mem_freelist_last;
  	uint page_size;
  	uint swap_pages_total;
  	uint swap_pages_free;

  	// Process-related
  	char proclist[10][16];
  	uint procsizes[10];
  	uint procphyssizes[10];
  	uint procpagefaultcnts[10];
	uint proc_count;
};