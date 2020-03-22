/** @file
  C Run-Time Libraries (CRT) Wrapper Implementation for OpenSSL-based
  Cryptographic Library.

Copyright (c) 2009 - 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <CrtLibSupport.h>
#include <Library/RngLib.h>

int rand (void)
{
  UINT32 Data;
  GetRandomNumber32 (&Data);
  return (int)Data;
}

int getentropy(uint8_t *random_array, size_t bytes_to_read) {
    UINTN  Count;
    UINT16 Rest;
    UINTN  Index;

    Count = bytes_to_read / 2;
    for (Index = 0; Index < Count; Index++) {
      GetRandomNumber16 ((UINT16 *)random_array + Index);
    }

    if ((bytes_to_read % 2) != 0) {
      GetRandomNumber16 (&Rest);
      *((UINT8 *)random_array + Count * 2) = (UINT8)(Rest & 0xFF);
    }
    return 1;
}

