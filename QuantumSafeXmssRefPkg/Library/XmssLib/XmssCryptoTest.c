#include <stdio.h>
#include <stdlib.h>

#include "params.h"
#include "xmss.h"
#include "utils.h"
#include <Library/TestStubLib.h>
#include <Library/MemoryAllocationLib.h>

#define MAX_FILE_NAME_LEN  256

void
MemoryUsageCheckBegin (
  char   *Name
  );

void
MemoryUsageCheckEnd (
  char   *Name
  );

#define XMSS_MODE   0
#define XMSSMT_MODE 1

UINT8 mMode = XMSS_MODE;

typedef struct {
    UINT8 mode;
    char  *param;
    char  *file_name;
} PARAM_STRUCT;

PARAM_STRUCT param_set[] = {
  {XMSS_MODE, "XMSS-SHA2_10_256", "10"},
//  {XMSS_MODE, "XMSS-SHA2_16_256", "10"},
//  {XMSS_MODE, "XMSS-SHA2_20_256", "16"},
  {XMSSMT_MODE, "XMSSMT-SHA2_20/2_256", "20_2"},
  {XMSSMT_MODE, "XMSSMT-SHA2_40/4_256", "40_4"},
  {XMSSMT_MODE, "XMSSMT-SHA2_60/6_256", "60_6"},
};

int XMSS_STR_TO_OID (uint32_t *oid, const char *s) {
    if (mMode == XMSS_MODE) {
        return xmss_str_to_oid (oid, s);
    } else {
        return xmssmt_str_to_oid (oid, s);
    }
}

int XMSS_PARSE_OID (void *params, const uint32_t oid) {
    if (mMode == XMSS_MODE) {
        return xmss_parse_oid (params, oid);
    } else {
        return xmssmt_parse_oid (params, oid);
    }
}

int XMSS_KEYPAIR (unsigned char *pk, unsigned char *sk, const uint32_t oid) {
    if (mMode == XMSS_MODE) {
        return xmss_keypair (pk, sk, oid);
    } else {
        return xmssmt_keypair (pk, sk, oid);
    }
}

int XMSS_SIGN (unsigned char *sk,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen) {
    if (mMode == XMSS_MODE) {
        return xmss_sign (sk, sm, smlen, m, mlen);
    } else {
        return xmssmt_sign (sk, sm, smlen, m, mlen);
    }
}

int XMSS_SIGN_OPEN (unsigned char *m, unsigned long long *mlen,
                   const unsigned char *sm, unsigned long long smlen,
                   const unsigned char *pk) {
    if (mMode == XMSS_MODE) {
        return xmss_sign_open (m, mlen, sm, smlen, pk);
    } else {
        return xmssmt_sign_open (m, mlen, sm, smlen, pk);
    }
}

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

int keygen(char *param_name, char *keypair_file_name)
{
    xmss_params params;
    uint32_t oid = 0;
    int parse_oid_result = 0;

    XMSS_STR_TO_OID(&oid, param_name);
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
      write_file (keypair_file_name, buffer, pk_buffer_len + sk_buffer_len);
      free (buffer);
    }

    return 0;
}

int sign(char *keypair_file_name, char *m_file_name, char *sm_file_name) {
    uint8_t *keypair_file_buffer;
    uint8_t *m_file_buffer;

    xmss_params params;
    uint32_t oid_pk = 0;
    uint32_t oid_sk = 0;
    uint8_t buffer[XMSS_OID_LEN];
    int parse_oid_result;

    unsigned long long mlen;
    unsigned long long keypair_len;

    keypair_len = 0;
    keypair_file_buffer = read_file (keypair_file_name, &keypair_len);
    if (keypair_file_buffer == NULL) {
        fprintf(stderr, "Could not open keypair file.\n");
        return -1;
    }

    mlen = 0;
    m_file_buffer = read_file (m_file_name, &mlen);
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
    write_file (keypair_file_name, keypair_file_buffer, keypair_len);
    write_file (sm_file_name, sm, smlen);

    free(keypair_file_buffer);
    free(m_file_buffer);

    free(m);
    free(sm);

    return 0;
}

int verify(char *keypair_file_name, char *sm_file_name) {
    FILE *keypair_file_buffer;
    FILE *sm_file_buffer;

    xmss_params params;
    uint32_t oid = 0;
    uint8_t buffer[XMSS_OID_LEN];
    int parse_oid_result;

    unsigned long long smlen;
    unsigned long long keypair_len;
    int ret;

    keypair_len = 0;
    keypair_file_buffer = read_file (keypair_file_name, &keypair_len);
    if (keypair_file_buffer == NULL) {
        fprintf(stderr, "Could not open keypair file.\n");
        return -1;
    }

    smlen = 0;
    sm_file_buffer = read_file (sm_file_name, &smlen);
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

VOID
ValidateXmssVerify (
    VOID
    )
{
    int i;
    char *keyname = 0;
    char *parmname = 0;
    char *m_file_name = "hello.bin";
    char *sm_file_name = "hello.bin.sig";
    unsigned char msg_buffer[] = {"hello, world!"};

    WriteFileFromBuffer (L"hello.bin", sizeof(msg_buffer), msg_buffer);

    for (i = 0; i < ARRAY_SIZE(param_set); i++) {
        mMode = param_set[i].mode;
        parmname = param_set[i].param;
        keyname = param_set[i].file_name;
        printf ("test - %s\n", parmname);

#ifdef NEED_GEN_KEY
        if (keygen(parmname, keyname) != 0) {
            printf( "Error creating keys\n" );
            break;
        }
#endif
        if (sign( keyname, m_file_name, sm_file_name) != 0) {
            printf( "Error signing\n" );
            break;
        }
        MemoryUsageCheckBegin ((char *)parmname);
        if (verify( keyname, sm_file_name ) != 0) {
            printf( "Error verifying\n" );
            MemoryUsageCheckEnd ((char *)parmname);
            break;
        }
        MemoryUsageCheckEnd ((char *)parmname);
    }

    printf ("test done!\n");
}

int main(int argc, char **argv) {
  printf ("\nUEFI-XMSS Wrapper Cryptosystem Testing: \n");
  printf ("-------------------------------------------- \n");

  printf ("UEFI-XMSS Verification: \n");
  ValidateXmssVerify ();
}