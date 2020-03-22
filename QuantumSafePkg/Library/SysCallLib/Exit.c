/** @file
  C Run-Time Libraries (CRT) Wrapper Implementation for OpenSSL-based
  Cryptographic Library.

Copyright (c) 2009 - 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <CrtLibSupport.h>
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>

void exit (int error)
{
  EFI_STATUS  Status;
  if (error == 0) {
    Status = EFI_SUCCESS;
  } else {
    Status = EFI_INVALID_PARAMETER;
  }
  gBS->Exit(gImageHandle, Status, 0, NULL);
}
