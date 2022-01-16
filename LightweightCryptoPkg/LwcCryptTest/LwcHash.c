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
#include "internal-blake2s.h"
#include "internal-sha256.h"

#define AEAD_MAX_HASH_LEN 64

const aead_hash_algorithm_t * m_hash_arg_list[] = {
// Comparison
    &internal_sha256_hash_algorithm,
    &internal_blake2s_hash_algorithm,
// AEAD+Hash
    // ASCON
    &ascon_hash_algorithm,
    &ascon_hasha_algorithm,
    &ascon_xof_algorithm,
    &ascon_xofa_algorithm,
    // Photon-Beetle
    &photon_beetle_hash_algorithm,
    // Sparkle
    &esch_256_hash_algorithm,
    &esch_256_xof_algorithm,
    &esch_384_hash_algorithm,
    &esch_384_xof_algorithm,
    // Xoodyak
    &xoodyak_hash_algorithm,
    // Romulus
    //&romulus_hash_algorithm,
    //&romulus_xof_algorithm,
};

void
MemoryUsageCheckBegin (
  char   *Name
  );

void
MemoryUsageCheckEnd (
  char   *Name
  );

unsigned char m_test_input[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

/* Test a hash algorithm */
static void test_hash(const aead_hash_algorithm_t *hash)
{
    unsigned char output[AEAD_MAX_HASH_LEN];
    (*hash->hash)(output, m_test_input, sizeof(m_test_input));
}

void ValidateLwcHash () {
  int index;
  const aead_hash_algorithm_t *hash;

  for (index = 0; index < sizeof(m_hash_arg_list)/sizeof(m_hash_arg_list[0]); index++) {
    hash = m_hash_arg_list[index];
    const char *alg_name = hash->name;

    MemoryUsageCheckBegin ((char *)alg_name);
    test_hash(hash);
    MemoryUsageCheckEnd ((char *)alg_name);
  }
  return ;
}
