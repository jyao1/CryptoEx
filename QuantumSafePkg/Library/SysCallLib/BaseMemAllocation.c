/** @file
  Base Memory Allocation Routines Wrapper for Crypto library over OpenSSL
  during PEI & DXE phases.

Copyright (c) 2009 - 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <CrtLibSupport.h>
#include <Library/MemoryAllocationLib.h>

#define MEMORY_INFO_DATA_SIGNATURE SIGNATURE_32('M', 'I', 'D', 'A')

typedef struct {
  UINT32                        Signature;
  // return from AllocatePool
  VOID                          *AllocatedAddress;
  UINTN                         AllocatedSize;
  // return to caller and be used by caller
  VOID                          *UsedAddress;
  UINTN                         UsedSize;
  LIST_ENTRY                    Link;
} MEMORY_INFO_DATA;

LIST_ENTRY  mMemoryProfileInfo = INITIALIZE_LIST_HEAD_VARIABLE (mMemoryProfileInfo);

BOOLEAN mNeedRecordMemoryUsage = FALSE;
UINTN   mMemoryCurrentUsage = 0;
UINTN   mMemoryPeakUsage = 0;

void StartRecordMemoryUsage ()
{
  mNeedRecordMemoryUsage = TRUE;
}

void StopRecordMemoryUsage ()
{
  mNeedRecordMemoryUsage = FALSE;
}

void ClearMemoryUsage ()
{
  mMemoryCurrentUsage = 0;
  mMemoryPeakUsage = 0;
}

UINTN GetMemoryCurrentUsage ()
{
  return mMemoryCurrentUsage;
}

UINTN GetMemoryPeakUsage ()
{
  return mMemoryPeakUsage;
}

VOID
AppendMemInfo (
  IN VOID  *AllocatedAddress,
  IN UINTN AllocatedSize,
  IN VOID  *UsedAddress,
  IN UINTN UsedSize
  )
{
  MEMORY_INFO_DATA *MemInfoData;

  MemInfoData = AllocateZeroPool (sizeof(MEMORY_INFO_DATA));
  ASSERT (MemInfoData != NULL);

  MemInfoData->Signature = MEMORY_INFO_DATA_SIGNATURE;
  MemInfoData->AllocatedAddress = AllocatedAddress;
  MemInfoData->AllocatedSize = AllocatedSize;
  MemInfoData->UsedAddress = UsedAddress;
  MemInfoData->UsedSize = UsedSize;

  InsertTailList (&mMemoryProfileInfo, &MemInfoData->Link);

  if (mNeedRecordMemoryUsage) {
    mMemoryCurrentUsage += UsedSize;
    if (mMemoryPeakUsage < mMemoryCurrentUsage) {
      mMemoryPeakUsage = mMemoryCurrentUsage;
    }
  }
}

MEMORY_INFO_DATA *
GetMemInfo (
  IN VOID  *UsedAddress
  )
{
  LIST_ENTRY       *MemInfoList;
  LIST_ENTRY       *MemInfoLink;
  MEMORY_INFO_DATA *MemInfoData;

  MemInfoList = &mMemoryProfileInfo;
  MemInfoData = NULL;
  for (MemInfoLink = MemInfoList->ForwardLink; MemInfoLink != MemInfoList; MemInfoLink = MemInfoLink->ForwardLink) {
    MemInfoData = CR (MemInfoLink, MEMORY_INFO_DATA, Link, MEMORY_INFO_DATA_SIGNATURE);
    if (MemInfoData->UsedAddress == UsedAddress) {
      break;
    }
  }

  if (MemInfoLink == MemInfoList) {
    return NULL;
  }
  return MemInfoData;
}

VOID
RemoveMemInfo (
  IN VOID  *UsedAddress
  )
{
  MEMORY_INFO_DATA *MemInfoData;

  MemInfoData = GetMemInfo (UsedAddress);
  ASSERT (MemInfoData != NULL);

  RemoveEntryList (&MemInfoData->Link);
  MemInfoData->Signature = 0;

  if (mNeedRecordMemoryUsage) {
    mMemoryCurrentUsage -= MemInfoData->UsedSize;
  }

  FreePool (MemInfoData);
}

//
// -- Memory-Allocation Routines --
//

/* Allocates memory blocks */
void *malloc (size_t size)
{
  VOID             *AllocatedAddress;

  AllocatedAddress = AllocateZeroPool (size);
  if (AllocatedAddress == NULL) {
    return NULL;
  }
  AppendMemInfo (AllocatedAddress, size, AllocatedAddress, size);

  return AllocatedAddress;
}

/* Reallocate memory blocks */
void *realloc (void *ptr, size_t size)
{
  VOID             *AllocatedAddress;
  MEMORY_INFO_DATA *MemInfoData;

  MemInfoData = GetMemInfo (ptr);
  ASSERT (MemInfoData != NULL);

  AllocatedAddress = ReallocatePool (MemInfoData->UsedSize, size, ptr);
  if (AllocatedAddress == NULL) {
    return NULL;
  }
  RemoveMemInfo (ptr);
  AppendMemInfo (AllocatedAddress, size, AllocatedAddress, size);
  return AllocatedAddress;
}

/* De-allocates or frees a memory block */
void free (void *ptr)
{
  if (ptr == NULL) {
    return ;
  }
  FreePool (ptr);
  RemoveMemInfo (ptr);
}

void *calloc (unsigned int num, unsigned int size)
{
  return malloc (num * size);
}

void *uefi_aligned_malloc(size_t size, size_t alignment)
{
  VOID             *AllocatedAddress;
  VOID             *UsedAddress;

  AllocatedAddress = AllocateZeroPool (size + alignment);
  if (AllocatedAddress == NULL) {
    return NULL;
  }
  if (alignment != 0) {
    UsedAddress = (VOID *)(((UINTN)AllocatedAddress + alignment - 1) & ~(alignment - 1));
  } else {
    UsedAddress = AllocatedAddress;
  }
  AppendMemInfo (AllocatedAddress, size + alignment, UsedAddress, size);

  return UsedAddress;
}

void uefi_aligned_free(void *palignedmem)
{
  MEMORY_INFO_DATA *MemInfoData;

  if (palignedmem == NULL) {
    return ;
  }

  MemInfoData = GetMemInfo (palignedmem);
  ASSERT (MemInfoData != NULL);

  FreePool (MemInfoData->AllocatedAddress);
  RemoveMemInfo (palignedmem);
}
