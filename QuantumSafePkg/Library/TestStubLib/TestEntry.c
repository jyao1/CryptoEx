/** @file
  App Support.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/TestStubLib.h>

int main(int argc, char **argv);

#define MAX_ARG_COUNT 10
#define MAX_ARG_LEN   64
char temp_argv[MAX_ARG_COUNT][MAX_ARG_LEN];

EFI_STATUS
EFIAPI
TestEntryMain (
  IN     EFI_HANDLE                 ImageHandle,
  IN     EFI_SYSTEM_TABLE           *SystemTable
  )
{
  int argc;
  char *argv[MAX_ARG_COUNT];
  int Index;

  GetArg ();

  argc = (int)Argc;
  for (Index = 0; Index < Argc; Index++) {
    argv[Index] = &temp_argv[Index][0];
    UnicodeStrToAsciiStrS (Argv[Index], argv[Index], MAX_ARG_LEN);
  }
  main (argc, argv);

  return EFI_SUCCESS;
}
