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

UEFI-LWC Wrapper Cryptosystem Testing: 
-------------------------------------------- 
UEFI-LWC AEAD: 
AES-128-GCM: Stack Used - 0x4C0 (2KB)
AES-128-GCM: Heap Used - 0x0 (0KB)
AES-192-GCM: Stack Used - 0x4C0 (2KB)
AES-192-GCM: Heap Used - 0x0 (0KB)
AES-256-GCM: Stack Used - 0x4C0 (2KB)
AES-256-GCM: Heap Used - 0x0 (0KB)
ChaChaPoly: Stack Used - 0x400 (1KB)
ChaChaPoly: Heap Used - 0x0 (0KB)
ASCON-128: Stack Used - 0x400 (1KB)
ASCON-128: Heap Used - 0x0 (0KB)
ASCON-128a: Stack Used - 0x400 (1KB)
ASCON-128a: Heap Used - 0x0 (0KB)
ASCON-80pq: Stack Used - 0x400 (1KB)
ASCON-80pq: Heap Used - 0x0 (0KB)
ASCON-128-Masked: Stack Used - 0x400 (1KB)
ASCON-128-Masked: Heap Used - 0x0 (0KB)
ASCON-128a-Masked: Stack Used - 0x400 (1KB)
ASCON-128a-Masked: Heap Used - 0x0 (0KB)
ASCON-80pq-Masked: Stack Used - 0x400 (1KB)
ASCON-80pq-Masked: Heap Used - 0x0 (0KB)
ASCON-128-SIV: Stack Used - 0x400 (1KB)
ASCON-128-SIV: Heap Used - 0x0 (0KB)
ASCON-128a-SIV: Stack Used - 0x400 (1KB)
ASCON-128a-SIV: Heap Used - 0x0 (0KB)
ASCON-80pq-SIV: Stack Used - 0x400 (1KB)
ASCON-80pq-SIV: Heap Used - 0x0 (0KB)
PHOTON-Beetle-AEAD-ENC-128: Stack Used - 0x590 (2KB)
PHOTON-Beetle-AEAD-ENC-128: Heap Used - 0x0 (0KB)
PHOTON-Beetle-AEAD-ENC-32: Stack Used - 0x590 (2KB)
PHOTON-Beetle-AEAD-ENC-32: Heap Used - 0x0 (0KB)
Schwaemm256-128: Stack Used - 0x400 (1KB)
Schwaemm256-128: Heap Used - 0x0 (0KB)
Schwaemm192-192: Stack Used - 0x400 (1KB)
Schwaemm192-192: Heap Used - 0x0 (0KB)
Schwaemm128-128: Stack Used - 0x400 (1KB)
Schwaemm128-128: Heap Used - 0x0 (0KB)
Schwaemm256-256: Stack Used - 0x400 (1KB)
Schwaemm256-256: Heap Used - 0x0 (0KB)
Xoodyak: Stack Used - 0x400 (1KB)
Xoodyak: Heap Used - 0x0 (0KB)
Xoodyak-Masked: Stack Used - 0x400 (1KB)
Xoodyak-Masked: Heap Used - 0x0 (0KB)
Dumbo: Stack Used - 0x630 (2KB)
Dumbo: Heap Used - 0x0 (0KB)
Jumbo: Stack Used - 0x670 (2KB)
Jumbo: Heap Used - 0x0 (0KB)
Delirium: Stack Used - 0x560 (2KB)
Delirium: Heap Used - 0x0 (0KB)
ISAP-K-128A: Stack Used - 0x400 (1KB)
ISAP-K-128A: Heap Used - 0x0 (0KB)
ISAP-A-128A: Stack Used - 0x400 (1KB)
ISAP-A-128A: Heap Used - 0x0 (0KB)
ISAP-K-128: Stack Used - 0x400 (1KB)
ISAP-K-128: Heap Used - 0x0 (0KB)
ISAP-A-128: Stack Used - 0x400 (1KB)
ISAP-A-128: Heap Used - 0x0 (0KB)
ISAP-K-128A-pk: Stack Used - 0x400 (1KB)
ISAP-K-128A-pk: Heap Used - 0x0 (0KB)
ISAP-A-128A-pk: Stack Used - 0x400 (1KB)
ISAP-A-128A-pk: Heap Used - 0x0 (0KB)
ISAP-K-128-pk: Stack Used - 0x400 (1KB)
ISAP-K-128-pk: Heap Used - 0x0 (0KB)
ISAP-A-128-pk: Stack Used - 0x400 (1KB)
ISAP-A-128-pk: Heap Used - 0x0 (0KB)
GIFT-COFB: Stack Used - 0x400 (1KB)
GIFT-COFB: Heap Used - 0x0 (0KB)
GIFT-COFB-Masked: Stack Used - 0x930 (3KB)
GIFT-COFB-Masked: Heap Used - 0x0 (0KB)
TinyJAMBU-128: Stack Used - 0x400 (1KB)
TinyJAMBU-128: Heap Used - 0x0 (0KB)
TinyJAMBU-192: Stack Used - 0x400 (1KB)
TinyJAMBU-192: Heap Used - 0x0 (0KB)
TinyJAMBU-256: Stack Used - 0x400 (1KB)
TinyJAMBU-256: Heap Used - 0x0 (0KB)
TinyJAMBU-128-Masked: Stack Used - 0x400 (1KB)
TinyJAMBU-128-Masked: Heap Used - 0x0 (0KB)
TinyJAMBU-192-Masked: Stack Used - 0x400 (1KB)
TinyJAMBU-192-Masked: Heap Used - 0x0 (0KB)
TinyJAMBU-256-Masked: Stack Used - 0x400 (1KB)
TinyJAMBU-256-Masked: Heap Used - 0x0 (0KB)
Romulus-M: Stack Used - 0x710 (2KB)
Romulus-M: Heap Used - 0x0 (0KB)
Romulus-N: Stack Used - 0x6A0 (2KB)
Romulus-N: Heap Used - 0x0 (0KB)
Romulus-T: Stack Used - 0xA20 (3KB)
Romulus-T: Heap Used - 0x0 (0KB)
Grain-128AEAD: Stack Used - 0x400 (1KB)
Grain-128AEAD: Heap Used - 0x0 (0KB)

UEFI-LWC HASH: 
SHA256: Stack Used - 0x400 (1KB)
SHA256: Heap Used - 0x0 (0KB)
BLAKE2s: Stack Used - 0x400 (1KB)
BLAKE2s: Heap Used - 0x0 (0KB)
ASCON-HASH: Stack Used - 0x400 (1KB)
ASCON-HASH: Heap Used - 0x0 (0KB)
ASCON-HASHA: Stack Used - 0x400 (1KB)
ASCON-HASHA: Heap Used - 0x0 (0KB)
ASCON-XOF: Stack Used - 0x400 (1KB)
ASCON-XOF: Heap Used - 0x0 (0KB)
ASCON-XOFA: Stack Used - 0x400 (1KB)
ASCON-XOFA: Heap Used - 0x0 (0KB)
PHOTON-Beetle-HASH: Stack Used - 0x490 (2KB)
PHOTON-Beetle-HASH: Heap Used - 0x0 (0KB)
Esch256: Stack Used - 0x400 (1KB)
Esch256: Heap Used - 0x0 (0KB)
XOEsch256: Stack Used - 0x400 (1KB)
XOEsch256: Heap Used - 0x0 (0KB)
Esch384: Stack Used - 0x400 (1KB)
Esch384: Heap Used - 0x0 (0KB)
XOEsch384: Stack Used - 0x400 (1KB)
XOEsch384: Heap Used - 0x0 (0KB)
Xoodyak-Hash: Stack Used - 0x400 (1KB)
Xoodyak-Hash: Heap Used - 0x0 (0KB)

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
