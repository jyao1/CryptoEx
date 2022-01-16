/** @file
  App Support.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _TEST_STUB_LIB_H_
#define _TEST_STUB_LIB_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>

extern UINTN  Argc;
extern CHAR16 **Argv;

EFI_STATUS
GetArg (
  VOID
  );

EFI_STATUS
ReadFileToBuffer (
  IN  CHAR16                               *FileName,
  OUT UINTN                                *BufferSize,
  OUT VOID                                 **Buffer
  );

EFI_STATUS
WriteFileFromBuffer (
  IN  CHAR16                               *FileName,
  IN  UINTN                                BufferSize,
  IN  VOID                                 *Buffer
  );

VOID *
OpenFile (
  IN CHAR16   *FileName,
  IN BOOLEAN  IsRead
  );

EFI_STATUS
CloseFile (
  IN VOID *File
  );

EFI_STATUS
WriteFile (
  IN VOID  *File,
  IN VOID  *Buffer,
  IN UINTN BufferSize
  );

EFI_STATUS
ReadFileLine (
  IN VOID      *File,
  IN OUT VOID  *Buffer,
  IN OUT UINTN *BufferSize
  );

#endif