/** @file
  Base Memory Allocation Routines Wrapper for Crypto library over OpenSSL
  during PEI & DXE phases.

Copyright (c) 2009 - 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <CrtLibSupport.h>
#include <Library/MemoryAllocationLib.h>

//
// -- Memory-Allocation Routines --
//

/* Allocates memory blocks */
void *malloc (size_t size)
{
  return AllocateZeroPool (size);
}

/* Reallocate memory blocks */
void *realloc (void *ptr, size_t size)
{
  return ReallocatePool (size, size, ptr);
}

/* De-allocates or frees a memory block */
void free (void *ptr)
{
  if (ptr != NULL) {
    FreePool (ptr);
  }
}

void *calloc (unsigned int num, unsigned int size)
{
  return AllocateZeroPool (num * size);
}

void *uefi_aligned_malloc(size_t size, size_t alignment)
{
  // TBD
  return AllocateZeroPool (size);
}

void uefi_aligned_free(void *palignedmem)
{
  // TBD
  if (palignedmem != NULL) {
    FreePool (palignedmem);
  }
}
