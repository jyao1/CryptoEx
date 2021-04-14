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

UEFI-PQC Wrapper Cryptosystem Testing: 
-------------------------------------------- 
UEFI-PQC KEM: 
Classic-McEliece-348864: Stack Used - 0x21A3C0 (2153KB)
Classic-McEliece-348864: Heap Used - 0x417D4 (262KB)
Classic-McEliece-348864f: Stack Used - 0x21A3C0 (2153KB)
Classic-McEliece-348864f: Heap Used - 0x417D4 (262KB)
Classic-McEliece-460896: Stack Used - 0x48C0B0 (4657KB)
Classic-McEliece-460896: Heap Used - 0x8375C (526KB)
Classic-McEliece-460896f: Stack Used - 0x48C0B0 (4657KB)
Classic-McEliece-460896f: Heap Used - 0x8375C (526KB)
Classic-McEliece-6688128: Stack Used - 0x48C280 (4657KB)
Classic-McEliece-6688128: Heap Used - 0x102B54 (1035KB)
Classic-McEliece-6688128f: Stack Used - 0x48C280 (4657KB)
Classic-McEliece-6688128f: Heap Used - 0x102B54 (1035KB)
Classic-McEliece-6960119: Stack Used - 0x48C270 (4657KB)
Classic-McEliece-6960119: Heap Used - 0x10346D (1038KB)
Classic-McEliece-6960119f: Stack Used - 0x48C270 (4657KB)
Classic-McEliece-6960119f: Heap Used - 0x10346D (1038KB)
Classic-McEliece-8192128: Stack Used - 0x48C330 (4657KB)
Classic-McEliece-8192128: Heap Used - 0x14F210 (1341KB)
Classic-McEliece-8192128f: Stack Used - 0x48C330 (4657KB)
Classic-McEliece-8192128f: Heap Used - 0x14F210 (1341KB)
Kyber512: Stack Used - 0x2860 (11KB)
Kyber512: Heap Used - 0xDB0 (4KB)
Kyber768: Stack Used - 0x3BA0 (15KB)
Kyber768: Heap Used - 0x1370 (5KB)
Kyber1024: Stack Used - 0x5380 (21KB)
Kyber1024: Heap Used - 0x19D0 (7KB)
Kyber512-90s: Stack Used - 0x30D0 (13KB)
Kyber512-90s: Heap Used - 0xDF8 (4KB)
Kyber768-90s: Stack Used - 0x4410 (18KB)
Kyber768-90s: Heap Used - 0x13B8 (5KB)
Kyber1024-90s: Stack Used - 0x5BF0 (23KB)
Kyber1024-90s: Heap Used - 0x1A18 (7KB)
NTRU-HPS-2048-509: Stack Used - 0x6530 (26KB)
NTRU-HPS-2048-509: Heap Used - 0xA4D (3KB)
NTRU-HPS-2048-677: Stack Used - 0x8810 (35KB)
NTRU-HPS-2048-677: Heap Used - 0xD46 (4KB)
NTRU-HPS-4096-821: Stack Used - 0xA220 (41KB)
NTRU-HPS-4096-821: Heap Used - 0x1102 (5KB)
NTRU-HRSS-701: Stack Used - 0x82B0 (33KB)
NTRU-HRSS-701: Heap Used - 0xFBE (4KB)
ntrulpr653: Stack Used - 0x3E60 (16KB)
ntrulpr653: Heap Used - 0xE07 (4KB)
ntrulpr761: Stack Used - 0x4790 (18KB)
ntrulpr761: Heap Used - 0xFCC (4KB)
ntrulpr857: Stack Used - 0x4FE0 (20KB)
ntrulpr857: Heap Used - 0x1197 (5KB)
sntrup653: Stack Used - 0x3040 (13KB)
sntrup653: Heap Used - 0xEC9 (4KB)
sntrup761: Stack Used - 0x37D0 (14KB)
sntrup761: Heap Used - 0x10F0 (5KB)
sntrup857: Stack Used - 0x3EC0 (16KB)
sntrup857: Heap Used - 0x1311 (5KB)
LightSaber-KEM: Stack Used - 0x2AA0 (11KB)
LightSaber-KEM: Heap Used - 0xD98 (4KB)
Saber-KEM: Stack Used - 0x3A00 (15KB)
Saber-KEM: Heap Used - 0x1318 (5KB)
FireSaber-KEM: Stack Used - 0x5790 (22KB)
FireSaber-KEM: Heap Used - 0x18B8 (7KB)
FrodoKEM-640-AES: Stack Used - 0x197C0 (102KB)
FrodoKEM-640-AES: Heap Used - 0x9B10 (39KB)
FrodoKEM-640-SHAKE: Stack Used - 0x13A40 (79KB)
FrodoKEM-640-SHAKE: Heap Used - 0x9B10 (39KB)
FrodoKEM-976-AES: Stack Used - 0x26C60 (156KB)
FrodoKEM-976-AES: Heap Used - 0xF6B8 (62KB)
FrodoKEM-976-SHAKE: Stack Used - 0x1DD00 (120KB)
FrodoKEM-976-SHAKE: Heap Used - 0xF6B8 (62KB)
FrodoKEM-1344-AES: Stack Used - 0x352A0 (213KB)
FrodoKEM-1344-AES: Heap Used - 0x152D8 (85KB)
FrodoKEM-1344-SHAKE: Stack Used - 0x28CA0 (164KB)
FrodoKEM-1344-SHAKE: Heap Used - 0x152D8 (85KB)
SIDH-p434: Stack Used - 0x1C70 (8KB)
SIDH-p434: Heap Used - 0x498 (2KB)
SIDH-p434-compressed: Stack Used - 0x10CB0 (68KB)
SIDH-p434-compressed: Heap Used - 0x38E (1KB)
SIDH-p503: Stack Used - 0x1BF0 (7KB)
SIDH-p503: Heap Used - 0x520 (2KB)
SIDH-p503-compressed: Stack Used - 0x15990 (87KB)
SIDH-p503-compressed: Heap Used - 0x3EE (1KB)
SIDH-p610: Stack Used - 0x2970 (11KB)
SIDH-p610: Heap Used - 0x60E (2KB)
SIDH-p610-compressed: Stack Used - 0x209E0 (131KB)
SIDH-p610-compressed: Heap Used - 0x496 (2KB)
SIDH-p751: Stack Used - 0x2F70 (12KB)
SIDH-p751: Heap Used - 0x730 (2KB)
SIDH-p751-compressed: Stack Used - 0x2EE00 (188KB)
SIDH-p751-compressed: Heap Used - 0x566 (2KB)
SIKE-p434: Stack Used - 0x1EF0 (8KB)
SIKE-p434: Heap Used - 0x5F2 (2KB)
SIKE-p434-compressed: Stack Used - 0x10CB0 (68KB)
SIKE-p434-compressed: Heap Used - 0x4E7 (2KB)
SIKE-p503: Stack Used - 0x1ED0 (8KB)
SIKE-p503: Heap Used - 0x6A6 (2KB)
SIKE-p503-compressed: Stack Used - 0x15990 (87KB)
SIKE-p503-compressed: Heap Used - 0x578 (2KB)
SIKE-p610: Stack Used - 0x2CD0 (12KB)
SIKE-p610: Heap Used - 0x7A8 (2KB)
SIKE-p610-compressed: Stack Used - 0x209E0 (131KB)
SIKE-p610-compressed: Heap Used - 0x635 (2KB)
SIKE-p751: Stack Used - 0x3230 (13KB)
SIKE-p751: Heap Used - 0x904 (3KB)
SIKE-p751-compressed: Stack Used - 0x2EE00 (188KB)
SIKE-p751-compressed: Heap Used - 0x73B (2KB)

UEFI-PQC SIG: 
picnic_L1_FS: Stack Used - 0x1A80 (7KB)
picnic_L1_FS: Heap Used - 0x2B24A (173KB)
picnic_L1_UR: Stack Used - 0x1A90 (7KB)
picnic_L1_UR: Heap Used - 0x3F75E (254KB)
picnic_L1_full: Stack Used - 0x1A80 (7KB)
picnic_L1_full: Heap Used - 0x28CD6 (164KB)
picnic_L3_FS: Stack Used - 0x1AA0 (7KB)
picnic_L3_FS: Heap Used - 0x5A506 (362KB)
picnic_L3_UR: Stack Used - 0x1AB0 (7KB)
picnic_L3_UR: Heap Used - 0x88422 (546KB)
picnic_L3_full: Stack Used - 0x1AA0 (7KB)
picnic_L3_full: Heap Used - 0x51AC5 (327KB)
picnic_L5_FS: Stack Used - 0x1AA0 (7KB)
picnic_L5_FS: Heap Used - 0x9412A (593KB)
picnic_L5_UR: Stack Used - 0x1AB0 (7KB)
picnic_L5_UR: Heap Used - 0xE2592 (906KB)
picnic_L5_full: Stack Used - 0x1AA0 (7KB)
picnic_L5_full: Heap Used - 0x8B6E0 (558KB)
picnic3_L1: Stack Used - 0x1010 (5KB)
picnic3_L1: Heap Used - 0x15D52B (1398KB)
picnic3_L3: Stack Used - 0x1050 (5KB)
picnic3_L3: Heap Used - 0x3223CC (3209KB)
picnic3_L5: Stack Used - 0x1050 (5KB)
picnic3_L5: Heap Used - 0x5D2FC0 (5964KB)
Dilithium2: Stack Used - 0xCE20 (52KB)
Dilithium2: Heap Used - 0x1920 (7KB)
Dilithium3: Stack Used - 0x13A20 (79KB)
Dilithium3: Heap Used - 0x24C9 (10KB)
Dilithium5: Stack Used - 0x1E220 (121KB)
Dilithium5: Heap Used - 0x2FBF (12KB)
Dilithium2-AES: Stack Used - 0xD640 (54KB)
Dilithium2-AES: Heap Used - 0x1920 (7KB)
Dilithium3-AES: Stack Used - 0x14240 (81KB)
Dilithium3-AES: Heap Used - 0x24C9 (10KB)
Dilithium5-AES: Stack Used - 0x1EA40 (123KB)
Dilithium5-AES: Heap Used - 0x2FBF (12KB)
Falcon-512: Stack Used - 0xABF0 (43KB)
Falcon-512: Heap Used - 0xCB0 (4KB)
Falcon-1024: Stack Used - 0x148A0 (83KB)
Falcon-1024: Heap Used - 0x16B0 (6KB)
Rainbow-I-Classic: Stack Used - 0x2BAA0 (175KB)
Rainbow-I-Classic: Heap Used - 0x40DFE (260KB)
Rainbow-I-Circumzenithal: Stack Used - 0x4F7F0 (318KB)
Rainbow-I-Circumzenithal: Heap Used - 0x281DE (161KB)
Rainbow-I-Compressed: Stack Used - 0x4F7F0 (318KB)
Rainbow-I-Compressed: Heap Used - 0xED3E (60KB)
Rainbow-III-Classic: Stack Used - 0xF2940 (971KB)
Rainbow-III-Classic: Heap Used - 0x170560 (1474KB)
Rainbow-III-Circumzenithal: Stack Used - 0x1AF4C0 (1726KB)
Rainbow-III-Circumzenithal: Heap Used - 0xD9960 (871KB)
Rainbow-III-Compressed: Stack Used - 0x1AF4C0 (1726KB)
Rainbow-III-Compressed: Heap Used - 0x40C20 (260KB)
Rainbow-V-Classic: Stack Used - 0x217910 (2143KB)
Rainbow-V-Classic: Heap Used - 0x32F6B8 (3262KB)
Rainbow-V-Circumzenithal: Stack Used - 0x3AF470 (3774KB)
Rainbow-V-Circumzenithal: Heap Used - 0x1DAF98 (1900KB)
Rainbow-V-Compressed: Stack Used - 0x3AF470 (3774KB)
Rainbow-V-Compressed: Heap Used - 0x830F8 (525KB)
SPHINCS+-Haraka-128f-robust: Stack Used - 0x1510 (6KB)
SPHINCS+-Haraka-128f-robust: Heap Used - 0x435C (17KB)
SPHINCS+-Haraka-128f-simple: Stack Used - 0x1500 (6KB)
SPHINCS+-Haraka-128f-simple: Heap Used - 0x435C (17KB)
SPHINCS+-Haraka-128s-robust: Stack Used - 0x1450 (6KB)
SPHINCS+-Haraka-128s-robust: Heap Used - 0x209C (9KB)
SPHINCS+-Haraka-128s-simple: Stack Used - 0x1440 (6KB)
SPHINCS+-Haraka-128s-simple: Heap Used - 0x209C (9KB)
SPHINCS+-Haraka-192f-robust: Stack Used - 0x1A50 (7KB)
SPHINCS+-Haraka-192f-robust: Heap Used - 0x8C8C (36KB)
SPHINCS+-Haraka-192f-simple: Stack Used - 0x1A40 (7KB)
SPHINCS+-Haraka-192f-simple: Heap Used - 0x8C8C (36KB)
SPHINCS+-Haraka-192s-robust: Stack Used - 0x1A40 (7KB)
SPHINCS+-Haraka-192s-robust: Heap Used - 0x43E4 (17KB)
SPHINCS+-Haraka-192s-simple: Stack Used - 0x1A30 (7KB)
SPHINCS+-Haraka-192s-simple: Heap Used - 0x43E4 (17KB)
SPHINCS+-Haraka-256f-robust: Stack Used - 0x20E0 (9KB)
SPHINCS+-Haraka-256f-robust: Heap Used - 0xC1AC (49KB)
SPHINCS+-Haraka-256f-simple: Stack Used - 0x20D0 (9KB)
SPHINCS+-Haraka-256f-simple: Heap Used - 0xC1AC (49KB)
SPHINCS+-Haraka-256s-robust: Stack Used - 0x21F0 (9KB)
SPHINCS+-Haraka-256s-robust: Heap Used - 0x75CC (30KB)
SPHINCS+-Haraka-256s-simple: Stack Used - 0x21E0 (9KB)
SPHINCS+-Haraka-256s-simple: Heap Used - 0x75CC (30KB)
SPHINCS+-SHA256-128f-robust: Stack Used - 0xF80 (4KB)
SPHINCS+-SHA256-128f-robust: Heap Used - 0x43AC (17KB)
SPHINCS+-SHA256-128f-simple: Stack Used - 0xEF0 (4KB)
SPHINCS+-SHA256-128f-simple: Heap Used - 0x43AC (17KB)
SPHINCS+-SHA256-128s-robust: Stack Used - 0xFC8 (4KB)
SPHINCS+-SHA256-128s-robust: Heap Used - 0x20EC (9KB)
SPHINCS+-SHA256-128s-simple: Stack Used - 0xE88 (4KB)
SPHINCS+-SHA256-128s-simple: Heap Used - 0x20EC (9KB)
SPHINCS+-SHA256-192f-robust: Stack Used - 0x14C0 (6KB)
SPHINCS+-SHA256-192f-robust: Heap Used - 0x8CDC (36KB)
SPHINCS+-SHA256-192f-simple: Stack Used - 0x1420 (6KB)
SPHINCS+-SHA256-192f-simple: Heap Used - 0x8CDC (36KB)
SPHINCS+-SHA256-192s-robust: Stack Used - 0x1638 (6KB)
SPHINCS+-SHA256-192s-robust: Heap Used - 0x4434 (18KB)
SPHINCS+-SHA256-192s-simple: Stack Used - 0x1420 (6KB)
SPHINCS+-SHA256-192s-simple: Heap Used - 0x4434 (18KB)
SPHINCS+-SHA256-256f-robust: Stack Used - 0x1CE8 (8KB)
SPHINCS+-SHA256-256f-robust: Heap Used - 0xC1FC (49KB)
SPHINCS+-SHA256-256f-simple: Stack Used - 0x1AD0 (7KB)
SPHINCS+-SHA256-256f-simple: Heap Used - 0xC1FC (49KB)
SPHINCS+-SHA256-256s-robust: Stack Used - 0x1E38 (8KB)
SPHINCS+-SHA256-256s-robust: Heap Used - 0x761C (30KB)
SPHINCS+-SHA256-256s-simple: Stack Used - 0x1BE0 (7KB)
SPHINCS+-SHA256-256s-simple: Heap Used - 0x761C (30KB)
SPHINCS+-SHAKE256-128f-robust: Stack Used - 0xF60 (4KB)
SPHINCS+-SHAKE256-128f-robust: Heap Used - 0x442C (18KB)
SPHINCS+-SHAKE256-128f-simple: Stack Used - 0xF50 (4KB)
SPHINCS+-SHAKE256-128f-simple: Heap Used - 0x442C (18KB)
SPHINCS+-SHAKE256-128s-robust: Stack Used - 0xF18 (4KB)
SPHINCS+-SHAKE256-128s-robust: Heap Used - 0x216C (9KB)
SPHINCS+-SHAKE256-128s-simple: Stack Used - 0xF08 (4KB)
SPHINCS+-SHAKE256-128s-simple: Heap Used - 0x216C (9KB)
SPHINCS+-SHAKE256-192f-robust: Stack Used - 0x1620 (6KB)
SPHINCS+-SHAKE256-192f-robust: Heap Used - 0x8D5C (36KB)
SPHINCS+-SHAKE256-192f-simple: Stack Used - 0x1610 (6KB)
SPHINCS+-SHAKE256-192f-simple: Heap Used - 0x8D5C (36KB)
SPHINCS+-SHAKE256-192s-robust: Stack Used - 0x1620 (6KB)
SPHINCS+-SHAKE256-192s-robust: Heap Used - 0x44B4 (18KB)
SPHINCS+-SHAKE256-192s-simple: Stack Used - 0x1610 (6KB)
SPHINCS+-SHAKE256-192s-simple: Heap Used - 0x44B4 (18KB)
SPHINCS+-SHAKE256-256f-robust: Stack Used - 0x1CD0 (8KB)
SPHINCS+-SHAKE256-256f-robust: Heap Used - 0xC27C (49KB)
SPHINCS+-SHAKE256-256f-simple: Stack Used - 0x1CC0 (8KB)
SPHINCS+-SHAKE256-256f-simple: Heap Used - 0xC27C (49KB)
SPHINCS+-SHAKE256-256s-robust: Stack Used - 0x1DE0 (8KB)
SPHINCS+-SHAKE256-256s-robust: Heap Used - 0x769C (30KB)
SPHINCS+-SHAKE256-256s-simple: Stack Used - 0x1DD0 (8KB)
SPHINCS+-SHAKE256-256s-simple: Heap Used - 0x769C (30KB)

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
