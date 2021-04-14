// SPDX-License-Identifier: MIT

#if defined(_WIN32)
#pragma warning(disable : 4244 4293)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

char * m_sig_arg_list[] = {
  OQS_SIG_alg_picnic_L1_FS,
  OQS_SIG_alg_picnic_L1_UR,
  OQS_SIG_alg_picnic_L1_full,
  OQS_SIG_alg_picnic_L3_FS,
  OQS_SIG_alg_picnic_L3_UR,
  OQS_SIG_alg_picnic_L3_full,
  OQS_SIG_alg_picnic_L5_FS,
  OQS_SIG_alg_picnic_L5_UR,
  OQS_SIG_alg_picnic_L5_full,
  OQS_SIG_alg_picnic3_L1,
  OQS_SIG_alg_picnic3_L3,
  OQS_SIG_alg_picnic3_L5,
  OQS_SIG_alg_dilithium_2,
  OQS_SIG_alg_dilithium_3,
  OQS_SIG_alg_dilithium_5,
  OQS_SIG_alg_dilithium_2_aes,
  OQS_SIG_alg_dilithium_3_aes,
  OQS_SIG_alg_dilithium_5_aes,
  OQS_SIG_alg_falcon_512,
  OQS_SIG_alg_falcon_1024,
  OQS_SIG_alg_rainbow_I_classic,
  OQS_SIG_alg_rainbow_I_circumzenithal,
  OQS_SIG_alg_rainbow_I_compressed,
  OQS_SIG_alg_rainbow_III_classic,
  OQS_SIG_alg_rainbow_III_circumzenithal,
  OQS_SIG_alg_rainbow_III_compressed,
  OQS_SIG_alg_rainbow_V_classic,
  OQS_SIG_alg_rainbow_V_circumzenithal,
  OQS_SIG_alg_rainbow_V_compressed,
  OQS_SIG_alg_sphincs_haraka_128f_robust,
  OQS_SIG_alg_sphincs_haraka_128f_simple,
  OQS_SIG_alg_sphincs_haraka_128s_robust,
  OQS_SIG_alg_sphincs_haraka_128s_simple,
  OQS_SIG_alg_sphincs_haraka_192f_robust,
  OQS_SIG_alg_sphincs_haraka_192f_simple,
  OQS_SIG_alg_sphincs_haraka_192s_robust,
  OQS_SIG_alg_sphincs_haraka_192s_simple,
  OQS_SIG_alg_sphincs_haraka_256f_robust,
  OQS_SIG_alg_sphincs_haraka_256f_simple,
  OQS_SIG_alg_sphincs_haraka_256s_robust,
  OQS_SIG_alg_sphincs_haraka_256s_simple,
  OQS_SIG_alg_sphincs_sha256_128f_robust,
  OQS_SIG_alg_sphincs_sha256_128f_simple,
  OQS_SIG_alg_sphincs_sha256_128s_robust,
  OQS_SIG_alg_sphincs_sha256_128s_simple,
  OQS_SIG_alg_sphincs_sha256_192f_robust,
  OQS_SIG_alg_sphincs_sha256_192f_simple,
  OQS_SIG_alg_sphincs_sha256_192s_robust,
  OQS_SIG_alg_sphincs_sha256_192s_simple,
  OQS_SIG_alg_sphincs_sha256_256f_robust,
  OQS_SIG_alg_sphincs_sha256_256f_simple,
  OQS_SIG_alg_sphincs_sha256_256s_robust,
  OQS_SIG_alg_sphincs_sha256_256s_simple,
  OQS_SIG_alg_sphincs_shake256_128f_robust,
  OQS_SIG_alg_sphincs_shake256_128f_simple,
  OQS_SIG_alg_sphincs_shake256_128s_robust,
  OQS_SIG_alg_sphincs_shake256_128s_simple,
  OQS_SIG_alg_sphincs_shake256_192f_robust,
  OQS_SIG_alg_sphincs_shake256_192f_simple,
  OQS_SIG_alg_sphincs_shake256_192s_robust,
  OQS_SIG_alg_sphincs_shake256_192s_simple,
  OQS_SIG_alg_sphincs_shake256_256f_robust,
  OQS_SIG_alg_sphincs_shake256_256f_simple,
  OQS_SIG_alg_sphincs_shake256_256s_robust,
  OQS_SIG_alg_sphincs_shake256_256s_simple,
};

void
MemoryUsageCheckBegin (
  char   *Name
  );

void
MemoryUsageCheckEnd (
  char   *Name
  );

static OQS_STATUS sig_test_correctness(const char *method_name) {

  OQS_SIG *sig = NULL;
  uint8_t *public_key = NULL;
  uint8_t *secret_key = NULL;
  uint8_t *message = NULL;
  size_t message_len = 100;
  uint8_t *signature = NULL;
  size_t signature_len;
  OQS_STATUS rc, ret = OQS_ERROR;

  sig = OQS_SIG_new(method_name);
  if (sig == NULL) {
    fprintf(stderr, "ERROR: OQS_SIG_new failed\n");
    goto err;
  }

  printf("================================================================================\n");
  printf("Sample computation for signature %s\n", sig->method_name);
  printf("================================================================================\n");

  public_key = malloc(sig->length_public_key);
  secret_key = malloc(sig->length_secret_key);
  message = malloc(message_len);
  signature = malloc(sig->length_signature);

  if ((public_key == NULL) || (secret_key == NULL) || (message == NULL) || (signature == NULL)) {
    fprintf(stderr, "ERROR: malloc failed\n");
    goto err;
  }

  OQS_randombytes(message, message_len);

  rc = OQS_SIG_keypair(sig, public_key, secret_key);
  if (rc != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: OQS_SIG_keypair failed\n");
    goto err;
  }

  rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
  if (rc != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
    goto err;
  }

  rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
  if (rc != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: OQS_SIG_verify failed\n");
    goto err;
  }

  /* modify the signature to invalidate it */
  OQS_randombytes(signature, signature_len);
  rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
  if (rc != OQS_ERROR) {
    fprintf(stderr, "ERROR: OQS_SIG_verify should have failed!\n");
    goto err;
  }
  printf("verification passes as expected\n");
  ret = OQS_SUCCESS;
  goto cleanup;

err:
  ret = OQS_ERROR;

cleanup:
  if (sig != NULL) {
    OQS_MEM_secure_free(secret_key, sig->length_secret_key);
  }
  OQS_MEM_insecure_free(public_key);
  OQS_MEM_insecure_free(message);
  OQS_MEM_insecure_free(signature);
  OQS_SIG_free(sig);

  return ret;
}

void ValidatePqcSig () {
  int index;

  for (index = 0; index < sizeof(m_sig_arg_list)/sizeof(m_sig_arg_list[0]); index++) {
    char *alg_name = m_sig_arg_list[index];
    if (!OQS_SIG_alg_is_enabled(alg_name)) {
      printf("Signature algorithm %s not enabled!\n", alg_name);
      continue;
    }

    OQS_randombytes_switch_algorithm("system");

    OQS_STATUS rc;
    MemoryUsageCheckBegin (alg_name);
    rc = sig_test_correctness(alg_name);
    MemoryUsageCheckEnd (alg_name);
  }
  return ;
}
