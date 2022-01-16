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

UINT64  mPerformance = 3ull * 1000 * 1000 * 1000; // 3GHz

UINT64  mStart;
UINT64  mElapsed;
EFI_TPL mOldTpl;

VOID
LwcPerfStart (
  VOID
  )
{
  mOldTpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);
  mStart = AsmReadTsc();
}

UINT64
LwcPerfEnd (
  VOID
  )
{
  mElapsed = AsmReadTsc() - mStart;
  gBS->RestoreTPL (mOldTpl);
  return mElapsed;
}

VOID
DumpPerfHeader (
  IN CHAR8 *Name
  )
{
  Print (L"\n%a,", Name);
}

VOID
DumpPerfTitleCipher (
  VOID
  )
{
  Print (L"\nAlgorithm,CipherEncrypt128(Ticks/Bytes),CipherEncrypt128(Bytes/Sec),CipherDecrypt128(Ticks/Bytes),CipherDecrypt128(Bytes/Sec),CipherEncrypt16(Ticks/Bytes),CipherEncrypt16(Bytes/Sec),CipherDecrypt16(Ticks/Bytes),CipherDecrypt16(Bytes/Sec)");
}

VOID
DumpPerfTitleHash (
  VOID
  )
{
  Print (L"\nAlgorithm,Hash1024(Ticks/Bytes),Hash1024(Bytes/Sec),Hash128(Ticks/Bytes),Hash128(Bytes/Sec),Hash16(Ticks/Bytes),Hash16(Bytes/Sec)");
}

VOID
DumpPerfInfo (
  IN CHAR16 *Name,
  IN UINT32 Bytes
  )
{
  //Print (L"    %s: ", Name);
  Print (L"%lld,", mElapsed / Bytes);
  //
  // 1 bytes  = (Elapse / PerBytes) Tick
  // 1 second = Perfermance Tick = Perfermance / (ElapseTime / PerBytes) bytes
  //
  Print (L"%lld,", mPerformance * Bytes / mElapsed );
}

VOID
Calibrate (
  VOID  
  )
{
  mStart = AsmReadTsc();
  gBS->Stall (1 * 1000 * 1000);
  mPerformance = AsmReadTsc() - mStart;
  Print (L"Calibrate: %lld MHz\n", mPerformance / 1000 / 1000);
}