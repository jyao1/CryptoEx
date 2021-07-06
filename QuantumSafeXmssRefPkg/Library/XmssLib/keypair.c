#include <stdio.h>
#include <stdint.h>

#include "params.h"
#include "xmss.h"
#include <Library/TestStubLib.h>

#define MAX_FILE_NAME_LEN  256

#ifdef XMSSMT
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_KEYPAIR xmssmt_keypair
#else
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_KEYPAIR xmss_keypair
#endif

int write_file(const char *filename, unsigned char *data, size_t len) {
    EFI_STATUS  Status;
    CHAR16      FileName[MAX_FILE_NAME_LEN];

    AsciiStrToUnicodeStrS (filename, FileName, MAX_FILE_NAME_LEN);
    Status = WriteFileFromBuffer (FileName, len, data);
    if (Status != EFI_SUCCESS) {
        printf ("update_private_key - %s error\n", (char *)filename);
        return 0;
    }

    return 1;
}

void *read_file( const char *filename, size_t *len ) {
    EFI_STATUS  Status;
    UINTN       BufferSize;
    VOID        *Buffer;
    CHAR16      FileName[MAX_FILE_NAME_LEN];

    AsciiStrToUnicodeStrS (filename, FileName, MAX_FILE_NAME_LEN);
    Status = ReadFileToBuffer (FileName, &BufferSize, (VOID **)&Buffer);
    if (Status != EFI_SUCCESS) {
        printf ("read_file - %s error\n", filename);
        return NULL;
    }
    if (len) *len = BufferSize;
    return Buffer;
}

int main(int argc, char **argv)
{
    xmss_params params;
    uint32_t oid = 0;
    int parse_oid_result = 0;

    if (argc != 3) {
        fprintf(stderr, "Expected parameter string (e.g. 'XMSS-SHA2_10_256') and keypair filename"
                        " as two parameter.\n"
                        "The keypair is written to file.\n");
        return -1;
    }

    XMSS_STR_TO_OID(&oid, argv[1]);
    parse_oid_result = XMSS_PARSE_OID(&params, oid);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing oid.\n");
        return parse_oid_result;
    }

    unsigned char pk[XMSS_OID_LEN + XMSS_PARAM_MAX_pk_bytes];
    unsigned char sk[XMSS_OID_LEN + XMSS_PARAM_MAX_sk_bytes];

    XMSS_KEYPAIR(pk, sk, oid);

    {
      uint8_t *buffer;
      int  pk_buffer_len = (int)(XMSS_OID_LEN + params.pk_bytes);
      int  sk_buffer_len = (int)(XMSS_OID_LEN + params.sk_bytes);
      buffer = malloc (pk_buffer_len + sk_buffer_len);
      memcpy (buffer, pk, pk_buffer_len);
      memcpy (buffer + pk_buffer_len, sk, sk_buffer_len);
      write_file (argv[2], buffer, pk_buffer_len + sk_buffer_len);
      free (buffer);
    }

    return 0;
}
