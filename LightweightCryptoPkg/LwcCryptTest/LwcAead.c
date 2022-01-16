/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "aead-metadata.h"
#include "internal-chachapoly.h"

#define AEAD_MAX_KEY_LEN 32
#define AEAD_MAX_NONCE_LEN 16
#define AEAD_MAX_AD_LEN 32
#define AEAD_MAX_DATA_LEN 256
#define AEAD_MAX_TAG_LEN 16

const aead_cipher_t * m_aead_arg_list[] = {
// Comparison
    &aesgcm128_cipher,
    &aesgcm192_cipher,
    &aesgcm256_cipher,
    &internal_chachapoly_cipher,
// AEAD+Hash
    // ASCON
    &ascon128_cipher,
    &ascon128a_cipher,
    &ascon80pq_cipher,
    &ascon128_masked_cipher,
    &ascon128a_masked_cipher,
    &ascon80pq_masked_cipher,
    &ascon128_siv_cipher,
    &ascon128a_siv_cipher,
    &ascon80pq_siv_cipher,
    // Photon-Beetle
    &photon_beetle_128_cipher,
    &photon_beetle_32_cipher,
    // Sparkle
    &schwaemm_256_128_cipher,
    &schwaemm_192_192_cipher,
    &schwaemm_128_128_cipher,
    &schwaemm_256_256_cipher,
    // Xoodyak
    &xoodyak_cipher,
    &xoodyak_masked_cipher,

// AEAD-Only
    // Elephant
    &dumbo_cipher,
    &jumbo_cipher,
    &delirium_cipher,
    // ISAP
    &isap_keccak_128a_cipher,
    &isap_ascon_128a_cipher,
    &isap_keccak_128_cipher,
    &isap_ascon_128_cipher,
    &isap_keccak_128a_pk_cipher,
    &isap_ascon_128a_pk_cipher,
    &isap_keccak_128_pk_cipher,
    &isap_ascon_128_pk_cipher,
    // GIFT-COFB
    &gift_cofb_cipher,
    &gift_cofb_masked_cipher,
    // TinyJambu
    &tiny_jambu_128_cipher,
    &tiny_jambu_192_cipher,
    &tiny_jambu_256_cipher,
    &tiny_jambu_128_masked_cipher,
    &tiny_jambu_192_masked_cipher,
    &tiny_jambu_256_masked_cipher,
    // Romulus
    &romulus_m_cipher,
    &romulus_n_cipher,
    &romulus_t_cipher,
    // Grain128-AEAD
    &grain128_aead_cipher,
};


void
MemoryUsageCheckBegin (
  char   *Name
  );

void
MemoryUsageCheckEnd (
  char   *Name
  );

/* Information about a test vector for an AEAD algorithm */
typedef struct
{
    const char *name;
    unsigned char key[AEAD_MAX_KEY_LEN];
    unsigned char nonce[AEAD_MAX_NONCE_LEN];
    unsigned char ad[AEAD_MAX_AD_LEN];
    unsigned ad_len;
    unsigned char ciphertext[AEAD_MAX_DATA_LEN + AEAD_MAX_TAG_LEN];
    unsigned char plaintext[AEAD_MAX_DATA_LEN];
    unsigned plaintext_len;

} aead_cipher_test_vector_t;

aead_cipher_test_vector_t  m_aead_cipher_test_vector[] = {
  {
    "dummy_test",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    AEAD_MAX_AD_LEN,
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    AEAD_MAX_DATA_LEN,
  },
};
unsigned char temp[AEAD_MAX_DATA_LEN + AEAD_MAX_TAG_LEN];
unsigned char temp2[AEAD_MAX_DATA_LEN + AEAD_MAX_TAG_LEN];

/* Test a cipher algorithm */
static int test_cipher_inner(const aead_cipher_t *cipher, const aead_cipher_test_vector_t *test_vector)
{
    unsigned ciphertext_len = test_vector->plaintext_len + cipher->tag_len;
    size_t len;
    int result;

    /* Test encryption */
    memset(temp, 0xAA, sizeof(temp));
    len = 0xBADBEEF;
    result = (*(cipher->encrypt))
        (temp, &len, test_vector->plaintext, test_vector->plaintext_len,
         test_vector->ad, test_vector->ad_len, test_vector->nonce,
         test_vector->key);
    if (result != 0 || len != ciphertext_len) {
      fprintf(stderr, "ERROR: encrypt failed\n");
    }

    /* Test decryption */
    memset(temp2, 0xAA, sizeof(temp2));
    len = 0xBADBEEF;
    result = (*(cipher->decrypt))
        (temp2, &len, temp, ciphertext_len,
         test_vector->ad, test_vector->ad_len, test_vector->nonce,
         test_vector->key);
    if (result != 0 || len != test_vector->plaintext_len) {
      fprintf(stderr, "ERROR: decrypt failed\n");
    }

    return 1;
}

static void test_cipher(const aead_cipher_t *cipher)
{
  int index;

  for (index = 0; index < sizeof(m_aead_cipher_test_vector)/sizeof(m_aead_cipher_test_vector[0]); index++) {
    test_cipher_inner (cipher, &m_aead_cipher_test_vector[index]);
  }
}

void ValidateLwcAead () {
  int index;
  const aead_cipher_t *cipher;

  for (index = 0; index < sizeof(m_aead_arg_list)/sizeof(m_aead_arg_list[0]); index++) {
    cipher = m_aead_arg_list[index];
    const char *alg_name = cipher->name;

    MemoryUsageCheckBegin ((char *)alg_name);
    test_cipher(cipher);
    MemoryUsageCheckEnd ((char *)alg_name);
  }
  return ;
}
