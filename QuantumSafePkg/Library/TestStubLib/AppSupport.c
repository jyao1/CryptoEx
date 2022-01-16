/** @file
  App Support.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/FileHandleLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/ShellParameters.h>
#include <Protocol/Shell.h>
#include <Guid/GlobalVariable.h>
#include <Guid/FileInfo.h>

UINTN  Argc;
CHAR16 **Argv;
EFI_SHELL_PROTOCOL      *mShellProtocol = NULL;

/**

  This function parse application ARG.

  @return Status
**/
EFI_STATUS
GetArg (
  VOID
  )
{
  EFI_STATUS                    Status;
  EFI_SHELL_PARAMETERS_PROTOCOL *ShellParameters;

  Status = gBS->HandleProtocol (
                  gImageHandle,
                  &gEfiShellParametersProtocolGuid,
                  (VOID**)&ShellParameters
                  );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Argc = ShellParameters->Argc;
  Argv = ShellParameters->Argv;
  return EFI_SUCCESS;
}

/**
  Get shell protocol.

  @return Pointer to shell protocol.
**/
EFI_SHELL_PROTOCOL *
GetShellProtocol (
  VOID
  )
{
  EFI_STATUS            Status;

  if (mShellProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gEfiShellProtocolGuid,
                    NULL,
                    (VOID **) &mShellProtocol
                    );
    if (EFI_ERROR (Status)) {
      mShellProtocol = NULL;
    }
  }

  return mShellProtocol;
}

/**
  Read a file.

  @param[in]  FileName        The file to be read.
  @param[out] BufferSize      The file buffer size
  @param[out] Buffer          The file buffer

  @retval EFI_SUCCESS    Read file successfully
  @retval EFI_NOT_FOUND  Shell protocol or file not found
  @retval others         Read file failed
**/
EFI_STATUS
ReadFileToBuffer (
  IN  CHAR16                               *FileName,
  OUT UINTN                                *BufferSize,
  OUT VOID                                 **Buffer
  )
{
  EFI_STATUS                        Status;
  EFI_SHELL_PROTOCOL                *ShellProtocol;
  SHELL_FILE_HANDLE                 Handle;
  UINT64                            FileSize;
  UINTN                             TempBufferSize;
  VOID                              *TempBuffer;

  ShellProtocol = GetShellProtocol();
  if (ShellProtocol == NULL) {
    return EFI_NOT_FOUND;
  }

  //
  // Open file by FileName.
  //
  Status = ShellProtocol->OpenFileByName (
                            FileName,
                            &Handle,
                            EFI_FILE_MODE_READ
                            );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Get the file size.
  //
  Status = ShellProtocol->GetFileSize (Handle, &FileSize);
  if (EFI_ERROR (Status)) {
    ShellProtocol->CloseFile (Handle);
    return Status;
  }

  TempBufferSize = (UINTN) FileSize;
  TempBuffer = AllocateZeroPool (TempBufferSize);
  if (TempBuffer == NULL) {
    ShellProtocol->CloseFile (Handle);
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Read the file data to the buffer
  //
  Status = ShellProtocol->ReadFile (
                            Handle,
                            &TempBufferSize,
                            TempBuffer
                            );
  if (EFI_ERROR (Status)) {
    ShellProtocol->CloseFile (Handle);
    return Status;
  }

  ShellProtocol->CloseFile (Handle);

  *BufferSize = TempBufferSize;
  *Buffer     = TempBuffer;
  return EFI_SUCCESS;
}

/**
  Write a file.

  @param[in] FileName        The file to be written.
  @param[in] BufferSize      The file buffer size
  @param[in] Buffer          The file buffer

  @retval EFI_SUCCESS    Write file successfully
  @retval EFI_NOT_FOUND  Shell protocol not found
  @retval others         Write file failed
**/
EFI_STATUS
WriteFileFromBuffer (
  IN  CHAR16                               *FileName,
  IN  UINTN                                BufferSize,
  IN  VOID                                 *Buffer
  )
{
  EFI_STATUS                        Status;
  EFI_SHELL_PROTOCOL                *ShellProtocol;
  SHELL_FILE_HANDLE                 Handle;
  EFI_FILE_INFO                     *FileInfo;
  UINTN                             TempBufferSize;

  ShellProtocol = GetShellProtocol();
  if (ShellProtocol == NULL) {
    return EFI_NOT_FOUND;
  }

  //
  // Open file by FileName.
  //
  Status = ShellProtocol->OpenFileByName (
                            FileName,
                            &Handle,
                            EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE
                            );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Empty the file contents.
  //
  FileInfo = ShellProtocol->GetFileInfo (Handle);
  if (FileInfo == NULL) {
    ShellProtocol->CloseFile (Handle);
    return EFI_DEVICE_ERROR;
  }

  //
  // If the file size is already 0, then it has been empty.
  //
  if (FileInfo->FileSize != 0) {
    //
    // Set the file size to 0.
    //
    FileInfo->FileSize = 0;
    Status = ShellProtocol->SetFileInfo (Handle, FileInfo);
    if (EFI_ERROR (Status)) {
      FreePool (FileInfo);
      ShellProtocol->CloseFile (Handle);
      return Status;
    }
  }
  FreePool (FileInfo);

  //
  // Write the file data from the buffer
  //
  if (BufferSize != 0) {
    TempBufferSize = BufferSize;
    Status = ShellProtocol->WriteFile (
                              Handle,
                              &TempBufferSize,
                              Buffer
                              );
    if (EFI_ERROR (Status)) {
      ShellProtocol->CloseFile (Handle);
      return Status;
    }
  }

  ShellProtocol->CloseFile (Handle);

  return EFI_SUCCESS;
}

typedef struct {
  CHAR16          *FileName;
  VOID            *FileBuffer;
  UINTN           FileBufferMaxSize;
  UINTN           FileBufferSize;
  UINTN           ReadPosition;
} FILE_BUFFER;

#define FILE_BUFFER_MAX_SIZE 0x1000

VOID *
OpenFile (
  IN CHAR16   *FileName,
  IN BOOLEAN  IsRead
  )
{
  UINTN          BufferSize;
  VOID           *Buffer;
  FILE_BUFFER    *FileBuffer;
  UINTN          FileNameSize;
  EFI_STATUS     Status;

  if (IsRead) {
    Status = ReadFileToBuffer (FileName, &BufferSize, &Buffer);
  } else {
    Buffer = NULL;
    BufferSize = 0;
    Status = WriteFileFromBuffer (FileName, 0, NULL);
  }
  if (EFI_ERROR(Status)) {
    return NULL;
  }

  FileBuffer = AllocateZeroPool (sizeof(FILE_BUFFER));
  if (FileBuffer == NULL) {
    FreePool (Buffer);
    return NULL;
  }

  FileNameSize = StrSize (FileName);
  FileBuffer->FileName = AllocateZeroPool (FileNameSize);
  if (FileBuffer->FileName == NULL) {
    FreePool (Buffer);
    FreePool (FileBuffer);
    return NULL;
  }
  StrCpyS (FileBuffer->FileName, FileNameSize, FileName);
  if (BufferSize != 0) {
    FileBuffer->FileBuffer = Buffer;
    FileBuffer->FileBufferMaxSize = BufferSize;
    FileBuffer->FileBufferSize = BufferSize;
  } else {
    ASSERT (Buffer == NULL);
    FileBuffer->FileBuffer = AllocateZeroPool (FILE_BUFFER_MAX_SIZE);
    if (FileBuffer->FileBuffer == NULL) {
      FreePool (Buffer);
      FreePool (FileBuffer);
      return NULL;
    }
    FileBuffer->FileBufferMaxSize = FILE_BUFFER_MAX_SIZE;
    FileBuffer->FileBufferSize = 0;
  }
  FileBuffer->ReadPosition = 0;
  
  return FileBuffer;
}

EFI_STATUS
CloseFile (
  IN VOID *File
  )
{
  FILE_BUFFER    *FileBuffer;
  EFI_STATUS     Status;

  FileBuffer = File;

  Status = WriteFileFromBuffer (FileBuffer->FileName, FileBuffer->FileBufferSize, FileBuffer->FileBuffer);

  return Status;
}

EFI_STATUS
WriteFile (
  IN VOID  *File,
  IN VOID  *Buffer,
  IN UINTN BufferSize
  )
{
  FILE_BUFFER    *FileBuffer;
  UINTN          AddedBufferSize;
  VOID           *NewFileBuffer;

  FileBuffer = File;
  ASSERT (FileBuffer->FileBufferMaxSize >= FileBuffer->FileBufferSize);

  if (FileBuffer->FileBufferMaxSize - FileBuffer->FileBufferSize < BufferSize) {
    AddedBufferSize = (BufferSize > FILE_BUFFER_MAX_SIZE) ? BufferSize : FILE_BUFFER_MAX_SIZE;
    NewFileBuffer = ReallocatePool (
                      FileBuffer->FileBufferMaxSize,
                      FileBuffer->FileBufferMaxSize + AddedBufferSize,
                      FileBuffer->FileBuffer
                      );
    if (NewFileBuffer == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    FileBuffer->FileBufferMaxSize += AddedBufferSize;
    FileBuffer->FileBuffer = NewFileBuffer;
  }

  CopyMem (
    (UINT8 *)FileBuffer->FileBuffer + FileBuffer->FileBufferSize,
    Buffer,
    BufferSize
    );
  FileBuffer->FileBufferSize += BufferSize;

  return EFI_SUCCESS;
}

EFI_STATUS
ReadFileLine (
  IN VOID      *File,
  IN OUT VOID  *Buffer,
  IN OUT UINTN *BufferSize
  )
{
  FILE_BUFFER    *FileBuffer;
  UINTN          NewPosition;

  FileBuffer = File;
  ASSERT (FileBuffer->ReadPosition <= FileBuffer->FileBufferSize);

  if (*BufferSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (FileBuffer->ReadPosition == FileBuffer->FileBufferSize) {
    *(UINT8 *)Buffer = 0;
    *BufferSize = 1;
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // ReadPosition is always the (last + 1) byte of current buffer and the first bytes of next buffer.
  // For this function, (ReadPosition - 1) is '\n' or last byte of file.
  //
  for (NewPosition = FileBuffer->ReadPosition; NewPosition < FileBuffer->FileBufferSize; NewPosition++) {
    if (*((UINT8 *)FileBuffer->FileBuffer + NewPosition) == '\n') {
      break;
    }
  }

  if (NewPosition != FileBuffer->FileBufferSize) {
    // let NewPosition to be the next char
    NewPosition ++;
  }

  if (NewPosition > FileBuffer->ReadPosition + (*BufferSize - 1)) {
    NewPosition = FileBuffer->ReadPosition + (*BufferSize - 1);
  }
  *BufferSize = NewPosition - FileBuffer->ReadPosition + 1;

  CopyMem (
    Buffer,
    (UINT8 *)FileBuffer->FileBuffer + FileBuffer->ReadPosition,
    (*BufferSize - 1)
    );
  *((UINT8 *)Buffer + (*BufferSize - 1)) = 0;

  FileBuffer->ReadPosition = NewPosition;

  return EFI_SUCCESS;
}
