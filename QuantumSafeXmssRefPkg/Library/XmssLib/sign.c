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
    #define XMSS_SIGN xmssmt_sign
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_SIGN xmss_sign
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
    uint8_t *keypair_file_buffer;
    uint8_t *m_file_buffer;

    xmss_params params;
    uint32_t oid_pk = 0;
    uint32_t oid_sk = 0;
    uint8_t buffer[XMSS_OID_LEN];
    int parse_oid_result;

    unsigned long long mlen;
    unsigned long long keypair_len;

    if (argc != 4) {
        fprintf(stderr, "Expected keypair, message filenames, (signature + message) filename "
                        "as three parameters.\n"
                        "The keypair is updated with the changed state, "
                        "and the signature+message is output to file.\n");
        return -1;
    }

    keypair_len = 0;
    keypair_file_buffer = read_file (argv[1], &keypair_len);
    if (keypair_file_buffer == NULL) {
        fprintf(stderr, "Could not open keypair file.\n");
        return -1;
    }

    mlen = 0;
    m_file_buffer = read_file (argv[2], &mlen);
    if (m_file_buffer == NULL) {
        fprintf(stderr, "Could not open message file.\n");
        free (keypair_file_buffer);
        return -1;
    }

    /* Read the OID from the public key, as we need its length to seek past it */
    if (keypair_len <= XMSS_OID_LEN) {
        fprintf(stderr, "Could not parse keypair file.\n");
        free(keypair_file_buffer);
        free(m_file_buffer);
        return -1;
    }
    memcpy(&buffer, keypair_file_buffer, XMSS_OID_LEN);
    /* The XMSS_OID_LEN bytes in buffer are a big-endian uint32. */
    oid_pk = (uint32_t)bytes_to_ull(buffer, XMSS_OID_LEN);
    parse_oid_result = XMSS_PARSE_OID(&params, oid_pk);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing public key oid.\n");
        free(keypair_file_buffer);
        free(m_file_buffer);
        return parse_oid_result;
    }

    /* This is the OID we're actually going to use. Likely the same, but still. */
    memcpy(&buffer, keypair_file_buffer + XMSS_OID_LEN + params.pk_bytes, XMSS_OID_LEN);
    if (keypair_len <= XMSS_OID_LEN + params.pk_bytes + XMSS_OID_LEN) {
        fprintf(stderr, "Could not parse keypair file.\n");
        free(keypair_file_buffer);
        free(m_file_buffer);
        return -1;
    }
    oid_sk = (uint32_t)bytes_to_ull(buffer, XMSS_OID_LEN);
    parse_oid_result = XMSS_PARSE_OID(&params, oid_sk);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing secret key oid.\n");
        free(keypair_file_buffer);
        free(m_file_buffer);
        return parse_oid_result;
    }
    if (keypair_len != XMSS_OID_LEN + params.pk_bytes + XMSS_OID_LEN + params.sk_bytes) {
        fprintf(stderr, "Could not parse keypair file.\n");
        free(keypair_file_buffer);
        free(m_file_buffer);
        return -1;
    }

    unsigned char sk[XMSS_OID_LEN + XMSS_PARAM_MAX_sk_bytes];
    unsigned char *m = malloc(mlen);
    unsigned char *sm = malloc(params.sig_bytes + mlen);
    unsigned long long smlen;

    memcpy(sk, keypair_file_buffer + XMSS_OID_LEN + params.pk_bytes, XMSS_OID_LEN + params.sk_bytes);
    memcpy(m, m_file_buffer, mlen);

    XMSS_SIGN(sk, sm, &smlen, m, mlen);

    memcpy(keypair_file_buffer + XMSS_OID_LEN + params.pk_bytes + XMSS_OID_LEN, sk + XMSS_OID_LEN, params.sk_bytes);
    write_file (argv[1], keypair_file_buffer, keypair_len);
    write_file (argv[3], sm, smlen);

    free(keypair_file_buffer);
    free(m_file_buffer);

    free(m);
    free(sm);

    return 0;
}
