#include <stdio.h>
#include <stdlib.h>

#include "params.h"
#include "xmss.h"
#include "utils.h"
#include <Library/TestStubLib.h>
#include <Library/MemoryAllocationLib.h>

#define MAX_FILE_NAME_LEN  256

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_SIGN_OPEN xmssmt_sign_open
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_SIGN_OPEN xmss_sign_open
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

    void        *data;
    data = malloc (BufferSize);
    if (data == NULL) {
        FreePool (Buffer);
        return NULL;
    }
    memcpy(data, Buffer, BufferSize);
    FreePool (Buffer);

    return data;
}

int main(int argc, char **argv) {
    FILE *keypair_file_buffer;
    FILE *sm_file_buffer;

    xmss_params params;
    uint32_t oid = 0;
    uint8_t buffer[XMSS_OID_LEN];
    int parse_oid_result;

    unsigned long long smlen;
    unsigned long long keypair_len;
    int ret;

    if (argc != 3) {
        fprintf(stderr, "Expected keypair and (signature + message) filenames "
                        "as two parameters.\n"
                        "Keypair file needs only to contain the public key.\n"
                        "The return code 0 indicates verification success.\n");
        return -1;
    }

    keypair_len = 0;
    keypair_file_buffer = read_file (argv[1], &keypair_len);
    if (keypair_file_buffer == NULL) {
        fprintf(stderr, "Could not open keypair file.\n");
        return -1;
    }

    smlen = 0;
    sm_file_buffer = read_file (argv[2], &smlen);
    if (sm_file_buffer == NULL) {
        fprintf(stderr, "Could not open signature + message file.\n");
        free(keypair_file_buffer);
        return -1;
    }

    if (keypair_len <= XMSS_OID_LEN) {
        fprintf(stderr, "Could not parse keypair file.\n");
        free(keypair_file_buffer);
        free(sm_file_buffer);
        return -1;
    }
    memcpy(&buffer, keypair_file_buffer, XMSS_OID_LEN);
    oid = (uint32_t)bytes_to_ull(buffer, XMSS_OID_LEN);
    parse_oid_result = XMSS_PARSE_OID(&params, oid);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing oid.\n");
        free(keypair_file_buffer);
        free(sm_file_buffer);
        return parse_oid_result;
    }

    unsigned char pk[XMSS_OID_LEN + XMSS_PARAM_MAX_pk_bytes];
    unsigned char *sm = malloc(smlen);
    unsigned char *m = malloc(smlen);
    unsigned long long mlen;

    memcpy(pk, keypair_file_buffer, XMSS_OID_LEN + params.pk_bytes);
    memcpy(sm, sm_file_buffer, smlen);

    ret = XMSS_SIGN_OPEN(m, &mlen, sm, smlen, pk);

    if (ret) {
        printf("Verification failed!\n");
    }
    else {
        printf("Verification succeeded.\n");
    }

    free(keypair_file_buffer);
    free(sm_file_buffer);

    free(m);
    free(sm);

    return ret;
}
