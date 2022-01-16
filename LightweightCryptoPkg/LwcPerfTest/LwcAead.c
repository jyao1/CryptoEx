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

static int PERF_LOOPS = DEFAULT_PERF_LOOPS;
static int PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16;
static unsigned char PERF_MASKING = 0;

static unsigned char const key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char const nonce[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char plaintext[MAX_DATA_SIZE];
static unsigned char ciphertext[MAX_DATA_SIZE + MAX_TAG_SIZE];

static unsigned long encrypt_128_time = 0;
static unsigned long encrypt_16_time = 0;
static unsigned long decrypt_128_time = 0;
static unsigned long decrypt_16_time = 0;
static unsigned long encrypt_128_ref = 0;
static unsigned long encrypt_16_ref = 0;
static unsigned long decrypt_128_ref = 0;
static unsigned long decrypt_16_ref = 0;

void perfCipherEncrypt128(const aead_cipher_t *cipher)
{
    unsigned long long elapsed;
    size_t len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    LwcPerfStart();
    for (count = 0; count < PERF_LOOPS; ++count) {
        cipher->encrypt
            (ciphertext, &len, plaintext, 128, 0, 0, nonce, key);
    }
    elapsed = LwcPerfEnd();
    encrypt_128_time = elapsed;
    DumpPerfInfo (L"CipherEncrypt128", 128 * PERF_LOOPS);
}

void perfCipherDecrypt128(const aead_cipher_t *cipher)
{
    unsigned long long elapsed;
    size_t clen;
    size_t plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    cipher->encrypt(ciphertext, &clen, plaintext, 128, 0, 0, nonce, key);

    LwcPerfStart();
    for (count = 0; count < PERF_LOOPS; ++count) {
        cipher->decrypt
            (plaintext, &plen, ciphertext, clen, 0, 0, nonce, key);
    }
    elapsed = LwcPerfEnd();
    decrypt_128_time = elapsed;
    DumpPerfInfo (L"CipherDecrypt128", 128 * PERF_LOOPS);
}

void perfCipherEncrypt16(const aead_cipher_t *cipher)
{
    unsigned long long elapsed;
    size_t len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    LwcPerfStart();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->encrypt
            (ciphertext, &len, plaintext, 16, 0, 0, nonce, key);
    }
    elapsed = LwcPerfEnd();
    encrypt_16_time = elapsed;
    DumpPerfInfo (L"CipherEncrypt16", 16 * PERF_LOOPS_16);
}

void perfCipherDecrypt16(const aead_cipher_t *cipher)
{
    unsigned long long elapsed;
    size_t clen;
    size_t plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    cipher->encrypt(ciphertext, &clen, plaintext, 16, 0, 0, nonce, key);

    LwcPerfStart();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->decrypt
            (plaintext, &plen, ciphertext, clen, 0, 0, nonce, key);
    }
    elapsed = LwcPerfEnd();
    decrypt_16_time = elapsed;
    DumpPerfInfo (L"CipherDecrypt16", 16 * PERF_LOOPS_16);
}

void perfCipherSanityCheck(const aead_cipher_t *cipher, const char *sanity_vec)
{
    unsigned count;
    size_t clen;

    for (count = 0; count < 23; ++count)
        plaintext[count] = (unsigned char)count;
    for (count = 0; count < 11; ++count)
        plaintext[32 + count] = (unsigned char)count;

    cipher->encrypt
        (ciphertext, &clen, plaintext, 23, plaintext + 32, 11, nonce, key);
}

void perfCipher(const aead_cipher_t *cipher, const char *sanity_vec)
{
    DumpPerfHeader ((CHAR8 *)cipher->name);
    if (sanity_vec)
        perfCipherSanityCheck(cipher, sanity_vec);

    perfCipherEncrypt128(cipher);
    perfCipherDecrypt128(cipher);
    perfCipherEncrypt16(cipher);
    perfCipherDecrypt16(cipher);
}

void perfMasked(const aead_cipher_t *ref_cipher,
                const aead_cipher_t *masked_cipher)
{
    encrypt_128_ref = 0;
    decrypt_128_ref = 0;
    encrypt_16_ref = 0;
    decrypt_16_ref = 0;
    perfCipher(ref_cipher, 0);
    encrypt_128_ref = encrypt_128_time;
    decrypt_128_ref = decrypt_128_time;
    encrypt_16_ref = encrypt_16_time;
    decrypt_16_ref = decrypt_16_time;
    perfCipher(masked_cipher, 0);
}

void perfCipher_setup()
{
    // Test ChaChaPoly and BLAKE2s first to get the reference time
    // for other algorithms.
    perfCipher(&internal_chachapoly_cipher, 0);
    encrypt_128_ref = encrypt_128_time;
    decrypt_128_ref = decrypt_128_time;
    encrypt_16_ref = encrypt_16_time;
    decrypt_16_ref = decrypt_16_time;

    // Run performance tests on the NIST AEAD algorithms.
    //
    // The test vectors are for doing a quick sanity check that the
    // algorithm appears to be working correctly.  The test vector is:
    //      Key = 0001020304...    (up to the key length)
    //      Nonce = 0001020304...  (up to the nonce length)
    //      PT = 000102030405060708090A0B0C0D0E0F10111213141516  (size = 23)
    //      AD = 000102030405060708090A                          (size = 11)
    // Usually this is "Count = 771" in the standard NIST KAT vectors.
    perfCipher(&ascon128_cipher, "76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD69901F988A337A7239C411A18313622FC");
    perfCipher(&ascon128a_cipher, "C52E4E39F5EF9F8461912AED7ABBA1B8EB8AD7ACD54637D193C5371279753F2177BFC76E5FC300");
    perfCipher(&ascon80pq_cipher, "368D3F1F3BA75BA929D4A5327E8DE42A55383F238CCC04F75BF026EF5BE70D67741B339B908B04");
    perfCipher(&delirium_cipher, "1EBBE29D3EC4D574840905EFCEBFB40D02E1AB1B8B9994B8E19B5C7E461C77D276842CF6BEE6EA");
    perfCipher(&gift_cofb_cipher, "ABC3924173986D9EAA16CE0D01E923E5B6B26DC70E2190FB0E95FF754FF1A6943770CA3C04958A");
    perfCipher(&grain128_aead_cipher, "A4AB16F5B985B23EE9839C86A573B149D64EA150FEC21A81FD32406809DD51");
    perfCipher(&photon_beetle_128_cipher, "687B6BFD3807B447E418C8006C87A375AD55CEC555FA154A73EE361B62BBDA16875EDE631F445D");
    perfCipher(&photon_beetle_32_cipher, "05780949CD88CDC5940C408DD9ED28DD912386D437484DE5D4F65D10397CCE9E19F203840ACF2D");
    perfCipher(&romulus_n_cipher, "B0C179AC69E8583FD66B5C00368D4DBD93157CF52B93769A1EC2DF4019DE6D26A2FF2D31063F28");
    perfCipher(&romulus_m_cipher, "C21701C35E0E5FB450C66BD785B5E8A35426198531AD9BF1B30BB9ACC229A49C7C247BD28887DC");
    perfCipher(&romulus_t_cipher, "14431457C1B573058A16B8A10880FE96EF6ACAE8259E14523291D603D3A0066229A670554E094C");
    perfCipher(&schwaemm_256_128_cipher, "FA127C39BB1AB15429F59EF32F2742DB80A7F7A26939101E42502D7FB82673CF4977F6C6E12658");
    perfCipher(&schwaemm_192_192_cipher, "AED467CB67699D64AB5CE6AC4D578AA6C11AA962F639491095FD7DA7C3FE384B748518E9EEF24A4FF088466D3BE83B");
    perfCipher(&schwaemm_128_128_cipher, "8FC6A5B02165D2B9FF5838B24C7CFFC89F1A4BCB0AE9D1BEBBDAF0E435EF3D3B1E88283A992ADC");
    perfCipher(&schwaemm_256_256_cipher, "208CC82C35AF6227C7CF5C96A71BFBF10227D457DBD613F816C7704BA4AFF2E520BB179DAA1883D94212C18FD70EDDA2341E6058738F28");
    perfCipher(&tiny_jambu_128_cipher, "E30F24BBFC434EB18B92A3A4742BBAE61383F62BC9104E976569195FE559BC");
    perfCipher(&tiny_jambu_192_cipher, "317B8563AFA9B731FDF1F29FA688D0B0280422844CFEBAEE75CCE206898F65");
    perfCipher(&tiny_jambu_256_cipher, "D38B7389554B9C5DD8CA961C42CBE0017B102D0E01B82E91EAB122742F58F9");
    perfCipher(&xoodyak_cipher, "0E193FA578653462B128754C9CE9E5E4BB0910CA40C91A247E4EDCF2EC35E9098AF34EDF147366");

    // Performance of masked ciphers on their own.
    perfCipher(&ascon128_masked_cipher, "76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD69901F988A337A7239C411A18313622FC");
    perfCipher(&ascon128a_masked_cipher, "C52E4E39F5EF9F8461912AED7ABBA1B8EB8AD7ACD54637D193C5371279753F2177BFC76E5FC300");
    perfCipher(&ascon80pq_masked_cipher, "368D3F1F3BA75BA929D4A5327E8DE42A55383F238CCC04F75BF026EF5BE70D67741B339B908B04");
    perfCipher(&gift_cofb_masked_cipher, "ABC3924173986D9EAA16CE0D01E923E5B6B26DC70E2190FB0E95FF754FF1A6943770CA3C04958A");
    perfCipher(&tiny_jambu_128_masked_cipher, "E30F24BBFC434EB18B92A3A4742BBAE61383F62BC9104E976569195FE559BC");
    perfCipher(&tiny_jambu_192_masked_cipher, "317B8563AFA9B731FDF1F29FA688D0B0280422844CFEBAEE75CCE206898F65");
    perfCipher(&tiny_jambu_256_masked_cipher, "D38B7389554B9C5DD8CA961C42CBE0017B102D0E01B82E91EAB122742F58F9");
    perfCipher(&xoodyak_masked_cipher, "0E193FA578653462B128754C9CE9E5E4BB0910CA40C91A247E4EDCF2EC35E9098AF34EDF147366");

    // AES-GCM for comparison purposes.
    perfCipher(&aesgcm128_cipher, "936DA5CD621EF15343DB6B813AAE7E07A33708F547F8EB0B765EB53DA457F27E10BC0EA5FFB012");
    perfCipher(&aesgcm192_cipher, "E6F820989DBCCF09D83AD689F3A4D27F1E8E21182CB44015E3A161D7178FA543913F0659733BE7");
    perfCipher(&aesgcm256_cipher, "4703D418C1E0C41C85489D80BDE4766293C79527E46E4935C2431AA67EE0AFD558E563B09E1B8C");

    // Algorithms that are very slow.  Adjust loop counters and do them last.
    encrypt_128_ref /= 10;
    decrypt_128_ref /= 10;
    encrypt_16_ref /= 10;
    decrypt_16_ref /= 10;
    PERF_LOOPS = DEFAULT_PERF_LOOPS / 10;
    PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16 / 10;
    perfCipher(&dumbo_cipher, "0867290AD29D219C4BF3BF0BD652099B499B5B9CD7401BB862073E167E6543");
    perfCipher(&jumbo_cipher, "AE5D4F2BFAE6D432A1B6E92EB8955A7F2FD61692B269CDB16F7CA74F04CFE1");
    perfCipher(&isap_ascon_128a_cipher, "2CDE28DBBBD9131EBC568D77725B25937CF8EDB8A8F50A51312527CC6AEA52AED910035253C093");
    perfCipher(&isap_ascon_128_cipher, "B8529BCE1B3F9D0DB7A9C8DD43DD35D18E41801A814A2946E3500BD4A77E3EFF16EFABD6CCA575");
    perfCipher(&isap_keccak_128a_cipher, "01BC9CCB186E4A3732E86B9FAC4ABF3E6C4A8274A185FF1F7A1B9A98C623F126568CBADA74FAB5");
    perfCipher(&isap_keccak_128_cipher, "59D5A45BCBCB332311869B73F633D29606056B791F8A68F20CA7C894D7CDE7A06B357814696787");
  if (0) {
    // Comparison of masked and unmasked versions of ciphers.
    PERF_LOOPS = DEFAULT_PERF_LOOPS / 10;
    PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16 / 10;
    PERF_MASKING = 1;
    perfMasked(&ascon128_cipher, &ascon128_masked_cipher);
    perfMasked(&ascon128a_cipher, &ascon128a_masked_cipher);
    perfMasked(&ascon80pq_cipher, &ascon80pq_masked_cipher);
    perfMasked(&gift_cofb_cipher, &gift_cofb_masked_cipher);
    perfMasked(&tiny_jambu_128_cipher, &tiny_jambu_128_masked_cipher);
    perfMasked(&tiny_jambu_192_cipher, &tiny_jambu_192_masked_cipher);
    perfMasked(&tiny_jambu_256_cipher, &tiny_jambu_256_masked_cipher);
    perfMasked(&xoodyak_cipher, &xoodyak_masked_cipher);
  }
}

