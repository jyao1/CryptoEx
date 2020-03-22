/** @file
  C Run-Time Libraries (CRT) Wrapper Implementation for OpenSSL-based
  Cryptographic Library.

Copyright (c) 2009 - 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <CrtLibSupport.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>

#define MAX_DEBUG_MESSAGE_LENGTH  0x100

VOID
PatchFormat (
  IN  CONST CHAR8  *Format,
  IN OUT    CHAR8  *MyFormat
  )
{
  UINTN  Index;
  UINTN  MyIndex;

  Index = 0;
  MyIndex = 0;
  while (Format[Index] != 0) {
    MyFormat[MyIndex] = Format[Index];
    if (Format[Index] == '%') {
      Index++;
      MyIndex++;
      switch (Format[Index]) {
      case 's':
        MyFormat[MyIndex] = 'a';
        break;
      case 'z':
        if (Format[Index + 1] == 'u') {
          Index++;
          MyFormat[MyIndex] = 'd';
        }
        break;
      default:
        MyFormat[MyIndex] = Format[Index];
        break;
      }
    }
    Index++;
    MyIndex++;
  }
  MyFormat[MyIndex] = 0;
}

int printf(const char *format, ...)
{
  VA_LIST Marker;
  CHAR8   MyFormat[MAX_DEBUG_MESSAGE_LENGTH];

  VA_START (Marker, format);

  PatchFormat (format, MyFormat);

  DebugVPrint (DEBUG_INFO, MyFormat, Marker);
  
  VA_END (Marker);

  return 1;
}

int fprintf(FILE *file, const char *format, ...)
{
  VA_LIST Marker;
  CHAR8   MyFormat[MAX_DEBUG_MESSAGE_LENGTH];

  VA_START (Marker, format);

  PatchFormat (format, MyFormat);

  DebugVPrint (DEBUG_INFO, MyFormat, Marker);
  
  VA_END (Marker);

  return 1;
}

int sprintf(char *buf, const char *format, ...)
{
  VA_LIST Marker;
  CHAR8   MyFormat[MAX_DEBUG_MESSAGE_LENGTH];
  UINTN   Num;

  VA_START (Marker, format);

  PatchFormat (format, MyFormat);
  Num = AsciiVSPrint (buf, MAX_STRING_SIZE, MyFormat, Marker);
  
  VA_END (Marker);

  return (int)Num;
}