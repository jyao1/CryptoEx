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

#include <Base.h>

VOID
LwcPerfStart (
  VOID
  );

UINT64
LwcPerfEnd (
  VOID
  );

VOID
DumpPerfHeader (
  IN CHAR8 *Name
  );

VOID
DumpPerfInfo (
  IN CHAR16 *Name,
  IN UINT32 Bytes
  );

#define DEFAULT_PERF_LOOPS 1000
#define DEFAULT_PERF_LOOPS_16 3000
#define DEFAULT_PERF_HASH_LOOPS 1000

#define MAX_DATA_SIZE 128
#define MAX_TAG_SIZE 32

static int PERF_HASH_LOOPS = DEFAULT_PERF_HASH_LOOPS;

static unsigned long hash_1024_time = 0;
static unsigned long hash_128_time = 0;
static unsigned long hash_16_time = 0;
static unsigned long hash_1024_ref = 0;
static unsigned long hash_128_ref = 0;
static unsigned long hash_16_ref = 0;

static unsigned char hash_buffer[1024];

static unsigned char plaintext[MAX_DATA_SIZE];
static unsigned char ciphertext[MAX_DATA_SIZE + MAX_TAG_SIZE];

unsigned long perfHash_N
    (const aead_hash_algorithm_t *hash_alg, int size, unsigned long ref)
{
    unsigned long long elapsed;
    int count, loops;

    for (count = 0; count < size; ++count)
        hash_buffer[count] = (unsigned char)count;

    // Adjust the number of loops to do more loops on smaller sizes.
    if (size < 1024)
        loops = PERF_HASH_LOOPS * 4;
    else
        loops = PERF_HASH_LOOPS;

    LwcPerfStart();
    for (count = 0; count < loops; ++count) {
        hash_alg->hash(ciphertext, hash_buffer, size);
    }
    elapsed = LwcPerfEnd();
    switch (size) {
    case 1024:
        DumpPerfInfo (L"Hash1024", size * loops);
        break;
    case 128:
        DumpPerfInfo (L"Hash128", size * loops);
        break;
    case 16:
        DumpPerfInfo (L"Hash16", size * loops);
        break;
    default:
        break;
    }

    return elapsed;
}

void perfHashSanityCheck
    (const aead_hash_algorithm_t *hash_alg, const char *sanity_vec)
{
    unsigned count;

    for (count = 0; count < 23; ++count)
        plaintext[count] = (unsigned char)count;

    hash_alg->hash(ciphertext, plaintext, 23);
}

void perfHash(const aead_hash_algorithm_t *hash_alg, const char *sanity_vec)
{
    DumpPerfHeader ((CHAR8 *)hash_alg->name);
    if (sanity_vec)
        perfHashSanityCheck(hash_alg, sanity_vec);

    hash_1024_time = perfHash_N(hash_alg, 1024, hash_1024_ref);
    hash_128_time = perfHash_N(hash_alg, 128, hash_128_ref);
    hash_16_time = perfHash_N(hash_alg, 16, hash_16_ref);
}

void perfHash_setup()
{
    // Test ChaChaPoly and BLAKE2s first to get the reference time
    // for other algorithms.
    perfHash(&internal_blake2s_hash_algorithm, 0);
    hash_1024_ref = hash_1024_time;
    hash_128_ref = hash_128_time;
    hash_16_ref = hash_16_time;

    // Run performance tests on the NIST hash algorithms.
    // Sanity vector is the hash of the "Count = 24" NIST KAT vector:
    //      000102030405060708090A0B0C0D0E0F10111213141516
    perfHash(&ascon_hash_algorithm, "7876669F23C98AE89E6F98CACEF141E05BA6CC954E5787E6EE0D8385D7F93F55");
    perfHash(&ascon_hasha_algorithm, "628F10DC588CE8F67F08DD21B2A8C994E2D9F0D96968A5F7CE97E48A936D9A5C");
    perfHash(&esch_256_hash_algorithm, "E1F292177A096547DFDE7F1E2E33EFB6A7C4C6DAAA6AFC95C9521E5D13168AC3");
    perfHash(&esch_384_hash_algorithm, "DCAD7D7394C64CB59BE79EE06A42FE5A420C5718156C6D3CC44ED07E699DDBE79BB2919D65EC4A24B5ECE4AFB11DFF54");
    perfHash(&photon_beetle_hash_algorithm, "9DB4465229E011100FFA49C0500C3A7B2B154F29AFFD0291CA3EFF69A74DBA9E");
    perfHash(&romulus_hash_algorithm, "40055D86525079F0DB65F9DA46C6282D63B571C1DEE72BB3B5FB2C7319AB30EC");
    perfHash(&xoodyak_hash_algorithm, "511AD3AA185ACC22EB141A81C1EBDA05EADA4E0C07BFBAD3A4855DB3E96C2164");

    // SHA256 for comparison purposes.
    perfHash(&internal_sha256_hash_algorithm, 0);
}
