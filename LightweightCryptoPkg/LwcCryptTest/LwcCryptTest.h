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

#ifndef __CRYPTEST_H__
#define __CRYPTEST_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

/**
  Validate UEFI-LWC AEAD Interfaces.
**/
VOID
ValidateLwcAead (
  VOID
  );

/**
  Validate UEFI-LWC HASH Interfaces.
**/
VOID
ValidateLwcHash (
  VOID
  );

VOID
MemoryUsageCheckBegin (
  CHAR8   *Name
  );

VOID
MemoryUsageCheckEnd (
  CHAR8   *Name
  );

#endif
