/** @file
  Application for Cryptographic Primitives Validation.

Copyright (c) 2009 - 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/HobLib.h>
#include <Library/DebugLib.h>

/*
5_8: Stack Used - 0x1378 (5KB)
5_8: Heap Used - 0x564 (2KB)
5_8: Memory Leak - 0x3C
10_8: Stack Used - 0x1378 (5KB)
10_8: Heap Used - 0x605 (2KB)
10_8: Memory Leak - 0x3C
15_8: Stack Used - 0x1378 (5KB)
15_8: Heap Used - 0x6A5 (2KB)
15_8: Memory Leak - 0x3C
10_8,10_8: Stack Used - 0x1378 (5KB)
10_8,10_8: Heap Used - 0xBEE (3KB)
10_8,10_8: Memory Leak - 0x3C
15_8,10_8: Stack Used - 0x1378 (5KB)
15_8,10_8: Heap Used - 0xC8E (4KB)
15_8,10_8: Memory Leak - 0x3C
15_8,15_8: Stack Used - 0x1378 (5KB)
15_8,15_8: Heap Used - 0xD2E (4KB)
15_8,15_8: Memory Leak - 0x3C
*/

#define STACK_USAGE_SIGNATURE  0x5A5A5A5AA5A5A5A5ull

UINT8 *gStackBase;
UINTN gStackSize;

UINT64 gBeginAddress;

EFI_GUID mZeroGuid;

VOID StartRecordMemoryUsage ();
VOID StopRecordMemoryUsage ();
VOID ClearMemoryUsage ();
UINTN GetMemoryCurrentUsage ();
UINTN GetMemoryPeakUsage ();

EFI_STATUS
GetStackInfo (
  VOID
  )
{
  EFI_STATUS                  Status;
  VOID                        *HobList;
  EFI_PEI_HOB_POINTERS        Hob;
  EFI_HOB_MEMORY_ALLOCATION   *MemoryHob;
  UINT64                      UsedLength;
  
  //
  // Get Hob list
  //
  Status = EfiGetSystemConfigurationTable (&gEfiHobListGuid, &HobList);
  if (EFI_ERROR (Status)) {
    Print (L"HOB List not found\n");
    return EFI_NOT_FOUND;
  }

  for (Hob.Raw = HobList; !END_OF_HOB_LIST (Hob); Hob.Raw = GET_NEXT_HOB (Hob)) {
    if (GET_HOB_TYPE(Hob) == EFI_HOB_TYPE_MEMORY_ALLOCATION) {

      MemoryHob = Hob.MemoryAllocation;

      if (!CompareGuid(&mZeroGuid, &MemoryHob->AllocDescriptor.Name)) {
        if (CompareGuid(&gEfiHobMemoryAllocStackGuid, &MemoryHob->AllocDescriptor.Name)) {
#if VERBOSE
          Print(
            L"  Stack: Address=0x%lx  Length=0x%lx (%dKB)\n",
            MemoryHob->AllocDescriptor.MemoryBaseAddress,
            MemoryHob->AllocDescriptor.MemoryLength,
            MemoryHob->AllocDescriptor.MemoryLength / SIZE_1KB
            );
#endif
          gStackBase = (UINT8 *)(UINTN)MemoryHob->AllocDescriptor.MemoryBaseAddress;
          gStackSize = (UINTN)MemoryHob->AllocDescriptor.MemoryLength;
          UsedLength = MemoryHob->AllocDescriptor.MemoryBaseAddress + MemoryHob->AllocDescriptor.MemoryLength - (UINT64)(UINTN)&Status;
#if VERBOSE
          Print(
            L"  Current Stack: Address=0x%lx UsedLength=0x%lx (%dKB)\n",
            (UINT64)(UINTN)&Status,
            UsedLength,
            (UsedLength + SIZE_1KB - 1) / SIZE_1KB
            );
#endif
          return EFI_SUCCESS;
        }
      }
    }
  }
  Print (L"Stack Hob not found\n");
  return EFI_NOT_FOUND;
}

VOID
StackUsageCheckBegin (
  CHAR8   *Name
  )
{
  UINT64                      BeginAddress;

  GetStackInfo ();

  BeginAddress = (UINT64)(UINTN)&BeginAddress & ~0x7ull;
  gBeginAddress = BeginAddress;
  ASSERT (BeginAddress >= (UINTN)gStackBase);
  if (BeginAddress - (UINTN)gStackBase <= SIZE_4KB) {
    Print (L"StackUsageBegin fail - too small space\n");
    return ;
  }
#if VERBOSE
  Print (
    L"  Tag [0x%lx - 0x%lx]\n",
    (UINT64)(UINTN)gStackBase,
    (UINT64)(UINTN)gStackBase + BeginAddress- (UINTN)gStackBase - SIZE_1KB
    );
#endif
  SetMem64 (
    gStackBase,
    (UINTN)BeginAddress- (UINTN)gStackBase - SIZE_1KB,
    STACK_USAGE_SIGNATURE
    );
}

VOID
StackUsageCheckEnd (
  CHAR8   *Name
  )
{
  UINT64                      *Ptr;
  UINT64                      EndAddress;
  UINT64                      BeginAddress;
  UINTN                       DataLength;

  GetStackInfo ();

  EndAddress = 0;
  for (Ptr = (VOID *)gStackBase; (UINTN)Ptr < (UINTN)(gStackBase + gStackSize); Ptr+= 1) {
    if (*Ptr != STACK_USAGE_SIGNATURE) {
      EndAddress = (UINTN)Ptr;
      break;
    }
  }
  if (EndAddress == 0) {
    Print (L"StackUsageEnd fail - full space\n");
    return ;
  }

  DataLength = sizeof(UINT64);
  BeginAddress = gBeginAddress;
#if VERBOSE
  Print (L"  BeginAddress - 0x%lx, EndAddress - 0x%lx\n", BeginAddress, EndAddress);
#endif
  Print (
    L"%a: Stack Used - 0x%lx (%dKB)\n",
    Name,
    BeginAddress - EndAddress,
    (BeginAddress - EndAddress + SIZE_1KB - 1) / SIZE_1KB
    );
}

VOID
HeapUsageCheckBegin (
  CHAR8   *Name
  )
{
  StartRecordMemoryUsage ();
  ClearMemoryUsage ();
}

VOID
HeapUsageCheckEnd (
  CHAR8   *Name
  )
{
  UINTN MemoryPeakUsage;
  UINTN MemoryCurrentUsage;

  StopRecordMemoryUsage ();

  MemoryPeakUsage = GetMemoryPeakUsage ();
  Print (
    L"%a: Heap Used - 0x%x (%dKB)\n",
    Name,
    MemoryPeakUsage,
    (MemoryPeakUsage + SIZE_1KB - 1) / SIZE_1KB
    );
  MemoryCurrentUsage = GetMemoryCurrentUsage ();
  if (MemoryCurrentUsage != 0) {
    Print (
      L"%a: Memory Leak - 0x%x\n",
      Name,
      MemoryCurrentUsage
      );
  }
}

VOID
MemoryUsageCheckBegin (
  CHAR8   *Name
  )
{
  HeapUsageCheckBegin (Name);
  StackUsageCheckBegin (Name);
}

VOID
MemoryUsageCheckEnd (
  CHAR8   *Name
  )
{
  StackUsageCheckEnd (Name);
  HeapUsageCheckEnd (Name);
}
