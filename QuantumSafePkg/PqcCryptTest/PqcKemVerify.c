// SPDX-License-Identifier: MIT

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

char * m_kem_arg_list[] = {
  OQS_KEM_alg_bike1_l1_cpa,
  OQS_KEM_alg_bike1_l3_cpa,
  OQS_KEM_alg_bike1_l1_fo,
  OQS_KEM_alg_bike1_l3_fo,
  OQS_KEM_alg_classic_mceliece_348864,
  OQS_KEM_alg_classic_mceliece_348864f,
  OQS_KEM_alg_classic_mceliece_460896,
  OQS_KEM_alg_classic_mceliece_460896f,
  OQS_KEM_alg_classic_mceliece_6688128,
  OQS_KEM_alg_classic_mceliece_6688128f,
  OQS_KEM_alg_classic_mceliece_6960119,
  OQS_KEM_alg_classic_mceliece_6960119f,
  OQS_KEM_alg_classic_mceliece_8192128,
  OQS_KEM_alg_classic_mceliece_8192128f,
  OQS_KEM_alg_hqc_128,
  OQS_KEM_alg_hqc_192,
  OQS_KEM_alg_hqc_256,
  OQS_KEM_alg_kyber_512,
  OQS_KEM_alg_kyber_768,
  OQS_KEM_alg_kyber_1024,
  OQS_KEM_alg_kyber_512_90s,
  OQS_KEM_alg_kyber_768_90s,
  OQS_KEM_alg_kyber_1024_90s,
  OQS_KEM_alg_ntru_hps2048509,
  OQS_KEM_alg_ntru_hps2048677,
  OQS_KEM_alg_ntru_hps4096821,
  OQS_KEM_alg_ntru_hrss701,
  OQS_KEM_alg_ntruprime_ntrulpr653,
  OQS_KEM_alg_ntruprime_ntrulpr761,
  OQS_KEM_alg_ntruprime_ntrulpr857,
  OQS_KEM_alg_ntruprime_sntrup653,
  OQS_KEM_alg_ntruprime_sntrup761,
  OQS_KEM_alg_ntruprime_sntrup857,
  OQS_KEM_alg_saber_lightsaber,
  OQS_KEM_alg_saber_saber,
  OQS_KEM_alg_saber_firesaber,
  OQS_KEM_alg_frodokem_640_aes,
  OQS_KEM_alg_frodokem_640_shake,
  OQS_KEM_alg_frodokem_976_aes,
  OQS_KEM_alg_frodokem_976_shake,
  OQS_KEM_alg_frodokem_1344_aes,
  OQS_KEM_alg_frodokem_1344_shake,
  OQS_KEM_alg_sidh_p434,
  OQS_KEM_alg_sidh_p434_compressed,
  OQS_KEM_alg_sidh_p503,
  OQS_KEM_alg_sidh_p503_compressed,
  OQS_KEM_alg_sidh_p610,
  OQS_KEM_alg_sidh_p610_compressed,
  OQS_KEM_alg_sidh_p751,
  OQS_KEM_alg_sidh_p751_compressed,
  OQS_KEM_alg_sike_p434,
  OQS_KEM_alg_sike_p434_compressed,
  OQS_KEM_alg_sike_p503,
  OQS_KEM_alg_sike_p503_compressed,
  OQS_KEM_alg_sike_p610,
  OQS_KEM_alg_sike_p610_compressed,
  OQS_KEM_alg_sike_p751,
  OQS_KEM_alg_sike_p751_compressed,
};

void
MemoryUsageCheckBegin (
  char   *Name
  );

void
MemoryUsageCheckEnd (
  char   *Name
  );

/* Displays hexadecimal strings */
static void OQS_print_hex_string(const char *label, const uint8_t *str, size_t len) {
  printf("%-20s (%4zu bytes):  ", label, len);
  for (size_t i = 0; i < (len); i++) {
    printf("%02X", str[i]);
  }
  printf("\n");
}

typedef struct magic_s {
  uint8_t val[32];
} magic_t;

static OQS_STATUS kem_test_correctness(const char *method_name) {

  OQS_KEM *kem = NULL;
  uint8_t *public_key = NULL;
  uint8_t *secret_key = NULL;
  uint8_t *ciphertext = NULL;
  uint8_t *shared_secret_e = NULL;
  uint8_t *shared_secret_d = NULL;
  OQS_STATUS rc, ret = OQS_ERROR;
  int rv;

  //The magic numbers are 32 random values.
  //The length of the magic number was chosen arbitrarilly to 32.
  magic_t magic = {{
      0xfa, 0xfa, 0xfa, 0xfa, 0xbc, 0xbc, 0xbc, 0xbc,
      0x15, 0x61, 0x15, 0x61, 0x15, 0x61, 0x15, 0x61,
      0xad, 0xad, 0x43, 0x43, 0xad, 0xad, 0x34, 0x34,
      0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78
    }
  };

  kem = OQS_KEM_new(method_name);
  if (kem == NULL) {
    fprintf(stderr, "ERROR: OQS_KEM_new failed\n");
    goto err;
  }

  printf("================================================================================\n");
  printf("Sample computation for KEM %s\n", kem->method_name);
  printf("================================================================================\n");

  public_key = malloc(kem->length_public_key + sizeof(magic_t));
  secret_key = malloc(kem->length_secret_key + sizeof(magic_t));
  ciphertext = malloc(kem->length_ciphertext + sizeof(magic_t));
  shared_secret_e = malloc(kem->length_shared_secret + sizeof(magic_t));
  shared_secret_d = malloc(kem->length_shared_secret + sizeof(magic_t));

  //Set the magic numbers
  memcpy(public_key + kem->length_public_key, magic.val, sizeof(magic_t));
  memcpy(secret_key + kem->length_secret_key, magic.val, sizeof(magic_t));
  memcpy(ciphertext + kem->length_ciphertext, magic.val, sizeof(magic_t));
  memcpy(shared_secret_e + kem->length_shared_secret, magic.val, sizeof(magic_t));
  memcpy(shared_secret_d + kem->length_shared_secret, magic.val, sizeof(magic_t));

  if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) || (shared_secret_e == NULL) || (shared_secret_d == NULL)) {
    fprintf(stderr, "ERROR: malloc failed\n");
    goto err;
  }

  rc = OQS_KEM_keypair(kem, public_key, secret_key);
  if (rc != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: OQS_KEM_keypair failed\n");
    goto err;
  }

  rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
  if (rc != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: OQS_KEM_encaps failed\n");
    goto err;
  }

  rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
  if (rc != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: OQS_KEM_decaps failed\n");
    goto err;
  }

  rv = memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret);
  if (rv != 0) {
    fprintf(stderr, "ERROR: shared secrets are not equal\n");
    OQS_print_hex_string("shared_secret_e", shared_secret_e, kem->length_shared_secret);
    OQS_print_hex_string("shared_secret_d", shared_secret_d, kem->length_shared_secret);
    goto err;
  } else {
    printf("shared secrets are equal\n");
  }

  rv = memcmp(public_key + kem->length_public_key, magic.val, sizeof(magic_t));
  rv |= memcmp(secret_key + kem->length_secret_key, magic.val, sizeof(magic_t));
  rv |= memcmp(ciphertext + kem->length_ciphertext, magic.val, sizeof(magic_t));
  rv |= memcmp(shared_secret_e + kem->length_shared_secret, magic.val, sizeof(magic_t));
  rv |= memcmp(shared_secret_d + kem->length_shared_secret, magic.val, sizeof(magic_t));
  if (rv != 0) {
    fprintf(stderr, "ERROR: Magic numbers do not match\n");
    goto err;
  }

  // test invalid encapsulation (call should either fail or result in invalid shared secret)
  OQS_randombytes(ciphertext, kem->length_ciphertext);
  rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
  if (rc == OQS_SUCCESS && memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret) == 0) {
    fprintf(stderr, "ERROR: OQS_KEM_decaps succeeded on wrong input\n");
    goto err;
  }

  ret = OQS_SUCCESS;
  goto cleanup;

err:
  ret = OQS_ERROR;

cleanup:
  if (kem != NULL) {
    OQS_MEM_secure_free(secret_key, kem->length_secret_key);
    OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
    OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
  }
  OQS_MEM_insecure_free(public_key);
  OQS_MEM_insecure_free(ciphertext);
  OQS_KEM_free(kem);

  return ret;
}

void ValidatePqcKem () {
  int index;

  for (index = 0; index < sizeof(m_kem_arg_list)/sizeof(m_kem_arg_list[0]); index++) {
    char *alg_name = m_kem_arg_list[index];
    if (!OQS_KEM_alg_is_enabled(alg_name)) {
      printf("KEM algorithm %s not enabled!\n", alg_name);
      continue;
    }

    OQS_randombytes_switch_algorithm("system");

    OQS_STATUS rc;
    MemoryUsageCheckBegin (alg_name);
    rc = kem_test_correctness(alg_name);
    MemoryUsageCheckEnd (alg_name);
  }
  return ;
}
