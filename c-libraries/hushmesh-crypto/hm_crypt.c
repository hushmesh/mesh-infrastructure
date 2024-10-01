#ifndef ENCLAVE_BUILD
#include <wolfssl/options.h>
#endif

#include "hm_crypt.h"

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/signature.h>

#ifndef NO_KYBER
#include <wolfssl/wolfcrypt/ext_kyber.h>
#include <wolfssl/wolfcrypt/kyber.h>
#endif

#ifdef USE_RDSEED
#include <stdint.h>
#include <x86intrin.h>
#endif

#ifndef __OPTIMIZE__
// compilation is simpler if htonl() is defined inline
#define __OPTIMIZE__
#include <arpa/inet.h>
#undef __OPTIMIZE__
#else
#include <arpa/inet.h>
#endif

#define HEAP_HINT NULL
#define GCM_IV_LENGTH 12
#define GCM_AUTH_TAG_LENGTH 16
#define AES_KEY_SIZE 32
#define AES_KEY_SIZE_128 16
#define MAX_SECRET_SIZE 256
#define MAX_DER_SIZE 1024
#define MAX_RSA_DER_SIZE 4096
#define MAX_CERT_SIZE MAX_DER_SIZE // wolfssl's certgen example max is 4096
#define SHA256_SIZE 32
#define SHA384_SIZE 48
#define SHA512_SIZE 64
#define SHA1_SIZE 20
#define HASH_MAX_SIZE SHA512_SIZE
#define KEY_DECODE_BUF_SIZE 64
#define MAX_NAME_SIZE CTC_NAME_SIZE
#define SIGN_BUF_SIZE 512

static int mInit = false;
static hmc_status hmc_url_b64_encode(const unsigned char *data, size_t data_len,
                                     unsigned char *output,
                                     size_t output_max_len, size_t *output_len,
                                     bool nopadding);
static hmc_status hmc_url_b64_decode(const unsigned char *data, size_t data_len,
                                     unsigned char *output,
                                     size_t output_max_len, size_t *output_len);
static hmc_status hmc_b64_encode(const unsigned char *data, size_t data_len,
                                 unsigned char *output, size_t output_max_len,
                                 size_t *output_len);
static hmc_status hmc_b64_decode(const unsigned char *data, size_t data_len,
                                 unsigned char *output, size_t output_max_len,
                                 size_t *output_len);
static hmc_status hmc_hex_decode(const unsigned char *data, size_t data_len,
                                 unsigned char *output, size_t output_max_len,
                                 size_t *output_len);
static hmc_status hmc_hex_encode(const unsigned char *data, size_t data_len,
                                 unsigned char *output, size_t output_max_len,
                                 size_t *output_len);
static hmc_status hmc_sha256(const unsigned char *data, size_t data_len,
                             unsigned char *output);
static hmc_status hmc_sha384(const unsigned char *data, size_t data_len,
                             unsigned char *output);
static hmc_status hmc_sha512(const unsigned char *data, size_t data_len,
                             unsigned char *output);
static hmc_status hmc_sha1(const unsigned char *data, size_t data_len,
                           unsigned char *output);
static hmc_status hmc_decode_aes_key(Aes *aes, hmc_data_type key_data_type,
                                     const unsigned char *key, size_t key_len);
static hmc_status hmc_generate_ecc_key_pair(
    hmc_key_type key_type, hmc_data_type output_type,
    unsigned char *private_key_output, size_t private_key_output_max_len,
    size_t *private_key_output_len, unsigned char *public_key_output,
    size_t public_key_output_max_len, size_t *public_key_output_len);
static hmc_status hmc_generate_kyber_key_pair(
    hmc_key_type key_type, hmc_data_type output_type,
    unsigned char *private_key_output, size_t private_key_output_max_len,
    size_t *private_key_output_len, unsigned char *public_key_output,
    size_t public_key_output_max_len, size_t *public_key_output_len);
static hmc_status hmc_generate_rsa_key_pair(
    hmc_key_type key_type, hmc_data_type output_type,
    unsigned char *private_key_output, size_t private_key_output_max_len,
    size_t *private_key_output_len, unsigned char *public_key_output,
    size_t public_key_output_max_len, size_t *public_key_output_len);
static hmc_status hmc_read_public_ecc_key(hmc_data_type key_data_type,
                                          const unsigned char *input,
                                          size_t input_len, ecc_key *key);
static hmc_status hmc_read_private_ecc_key(hmc_data_type key_data_type,
                                           const unsigned char *input,
                                           size_t input_len, ecc_key *key);
static hmc_status hmc_read_private_rsa_key(hmc_data_type key_data_type, hmc_cred_type cred_type,
                                           const unsigned char *input,
                                           size_t input_len, RsaKey *key);
static hmc_status hmc_read_public_rsa_key(hmc_data_type key_data_type,
                                           const unsigned char *input,
                                           size_t input_len, RsaKey *key);
static hmc_status hmc_create_ecc_signature(
    hmc_key_type key_type, hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *input, size_t input_len, hmc_data_type output_type,
    unsigned char *output, size_t output_max_len, size_t *output_len);
static hmc_status hmc_create_rsa_signature(
    hmc_key_type key_type, hmc_cred_type cred_type, hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *input, size_t input_len, hmc_data_type output_type,
    unsigned char *output, size_t output_max_len, size_t *output_len);
static hmc_status
hmc_verify_ecc_signature(hmc_key_type key_type, hmc_data_type key_data_type,
                         const unsigned char *public_key, size_t public_key_len,
                         const unsigned char *input, size_t input_len,
                         hmc_sig_format signature_format,
                         hmc_data_type signature_data_type,
                         const unsigned char *signature, size_t signature_len,
                         bool *verified);
static hmc_status hmc_create_self_signed_ecc_certificate(
    const char *common_name, size_t common_name_len,
    int is_CA, int days_valid, unsigned char path_length,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type, hmc_data_type output_data_type,
    unsigned char *output, size_t output_max_len, size_t *output_len);
static hmc_status hmc_create_self_signed_ecc_certificate_internal(
    const char *common_name, size_t common_name_len,
    int is_CA, int days_valid, unsigned char path_length,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type, hmc_data_type output_data_type,
    unsigned char *output, size_t output_max_len, size_t *output_len);
static hmc_status hmc_create_certificate_internal(
    const unsigned char *csr, size_t csr_len, hmc_data_type csr_data_type,
    int is_intermediate_CA, int days_valid, unsigned char path_length,
    const unsigned char *ca_cert, size_t ca_cert_len,
    hmc_data_type ca_cert_data_type,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type,
    hmc_data_type output_data_type, unsigned char *output,
    size_t output_max_len, size_t *output_len);
static hmc_status hmc_create_ecc_certificate_internal(
    const unsigned char *csr, size_t csr_len, hmc_data_type csr_data_type,
    int is_intermediate_CA, int days_valid, unsigned char path_length,
    const unsigned char *ca_cert, size_t ca_cert_len,
    hmc_data_type ca_cert_data_type,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type,
    hmc_data_type output_data_type, unsigned char *output,
    size_t output_max_len, size_t *output_len);
static hmc_status hmc_create_ecc_certificate_signing_request(
    const char *common_name, size_t common_name_len,
    hmc_key_type key_type, hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    hmc_sig_type output_sig_type,
    hmc_data_type output_data_type, unsigned char *output,
    size_t output_max_len, size_t *output_len);

hmc_status hmc_init(hml_log_cb *logger_function) {
  if (mInit) {
    return HMC_STATUS_OK;
  }

  hml_set_log_cb(logger_function);
  int rc = wolfCrypt_Init();
  if (rc) {
    hml_error("wolfcrypt init failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  mInit = true;
  return HMC_STATUS_OK;
}

hmc_status hmc_generate_random(size_t len, hmc_data_type output_type,
                               unsigned char *output, size_t output_max_len,
                               size_t *output_len) {
  unsigned char key_data[len];
#ifdef USE_RDSEED
  // this will call hmc_generate_random
  int rc = wc_GenerateSeed(NULL, key_data, len);
  if (rc) {
    hml_error("call to generate seed failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
#else
  WC_RNG rng;

  int rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  rc = wc_RNG_GenerateBlock(&rng, key_data, len);
  if (rc) {
    hml_error("wolfcrypt generate block failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  wc_FreeRng(&rng);
#endif
  return hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, key_data, len,
                     HMC_HASH_TYPE_NONE, output_type, output, output_max_len,
                     output_len);
}

hmc_status hmc_encrypt(hmc_data_type key_data_type,
                       const unsigned char *key, size_t key_len,
                       const unsigned char *input, size_t input_len,
                       const unsigned char *aad, size_t aad_len,
                       hmc_data_type output_type,
                       unsigned char *output, size_t output_max_len,
                       size_t *output_len) {

  Aes aes_key;
  int rc;
  WC_RNG rng;
  unsigned char *ciphertext;
  bool need_convert = false;
  size_t ciphertext_alloc_len;

  hmc_status status = hmc_decode_aes_key(&aes_key, key_data_type, key, key_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    wc_AesFree(&aes_key);
    return HMC_STATUS_FAILURE;
  }

  if (output_type == HMC_DATA_TYPE_RAW) {
    ciphertext = output;
    if (output_max_len < (input_len + GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH)) {
      hml_error("output buffer too small");
      return HMC_STATUS_BUFFER_TOO_SMALL;
    }
  } else {
    ciphertext_alloc_len = input_len + GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH;
    ciphertext = malloc(ciphertext_alloc_len);
    need_convert = true;
  }
  rc = wc_RNG_GenerateBlock(&rng, ciphertext, GCM_IV_LENGTH);
  if (rc) {
    hml_error("generate block failed with %d", rc);
    if (need_convert) {
      free(ciphertext);
    }
    wc_FreeRng(&rng);
    wc_AesFree(&aes_key);
    return HMC_STATUS_FAILURE;
  }

  rc = wc_AesGcmEncrypt(&aes_key, ciphertext + GCM_IV_LENGTH, input, input_len,
                        ciphertext, GCM_IV_LENGTH,
                        ciphertext + GCM_IV_LENGTH + input_len,
                        GCM_AUTH_TAG_LENGTH, aad, aad_len);
  wc_AesFree(&aes_key);
  wc_FreeRng(&rng);
  if (rc) {
    if (need_convert) {
      free(ciphertext);
    }
    hml_error("encrypt failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  if (need_convert) {
    status = hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, ciphertext, ciphertext_alloc_len,
                     HMC_HASH_TYPE_NONE, output_type, output, output_max_len,
                     output_len);
    free(ciphertext);
    return status;
  }
  *output_len = input_len + GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH;
  return HMC_STATUS_OK;
}

hmc_status hmc_decrypt(hmc_data_type key_data_type, const unsigned char *key,
                       size_t key_len, hmc_data_type input_type,
                       const unsigned char *input, size_t input_len,
                       const unsigned char *aad, size_t aad_len,
                       hmc_data_type output_type, unsigned char *output,
                       size_t output_max_len, size_t *output_len) {

  Aes aes_key;
  int rc;
  unsigned char *ciphertext;
  bool need_convert_input = false;
  bool need_convert_output = false;
  size_t ciphertext_len = 0;
  unsigned char *decrypt_output;
  size_t ciphertext_alloc_len;

  hmc_status status = hmc_decode_aes_key(&aes_key, key_data_type, key, key_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  if (input_type == HMC_DATA_TYPE_RAW) {
    ciphertext = (unsigned char *) input;
    ciphertext_len = input_len;
  } else {
    ciphertext_alloc_len = input_len * 4;
    ciphertext = malloc(ciphertext_alloc_len);
    status = hmc_convert(input_type, HMC_CRED_TYPE_NONE, input, input_len, HMC_HASH_TYPE_NONE,
                       HMC_DATA_TYPE_RAW, ciphertext, ciphertext_alloc_len,
                       &ciphertext_len);
    if (status != HMC_STATUS_OK) {
      wc_AesFree(&aes_key);
      free(ciphertext);
      return status;
    }
    need_convert_input = true;
  }

  if (output_type == HMC_DATA_TYPE_RAW) {
    if (output_max_len < (ciphertext_len + 1)) {
      hml_error("output buffer too small");
      if (need_convert_input) {
        free(ciphertext);
      }
      wc_AesFree(&aes_key);
      return HMC_STATUS_BUFFER_TOO_SMALL;
    }
    decrypt_output = output;
  } else {
    decrypt_output = malloc(ciphertext_len + 1);
    need_convert_output = true;
  }

  if (ciphertext_len < (GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH)) {
    hml_error("decoded text is too short");
    if (need_convert_input) {
      free(ciphertext);
    }
    if (need_convert_output) {
      free(decrypt_output);
    }
    wc_AesFree(&aes_key);
    return HMC_STATUS_FAILURE;
  }

  ciphertext_len -= GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH;

  rc = wc_AesGcmDecrypt(&aes_key, (unsigned char *)decrypt_output,
                        ciphertext + GCM_IV_LENGTH, ciphertext_len, ciphertext,
                        GCM_IV_LENGTH,
                        ciphertext + GCM_IV_LENGTH + ciphertext_len,
                        GCM_AUTH_TAG_LENGTH, aad, aad_len);

  if (need_convert_input) {
    free(ciphertext);
  }
  wc_AesFree(&aes_key);
  if (rc) {
    hml_error("decrypt failed with %d", rc);
    if (need_convert_output) {
      free(decrypt_output);
    }
    return HMC_STATUS_FAILURE;
  }

  decrypt_output[ciphertext_len] = '\0';

  if (need_convert_output) {
    status = hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, decrypt_output, ciphertext_len,
                     HMC_HASH_TYPE_NONE, output_type, output, output_max_len,
                     output_len);
    free(decrypt_output);
    return status;
  }
  *output_len = ciphertext_len;
  return HMC_STATUS_OK;
}

hmc_status hmc_hmac_sign(hmc_data_type key_data_type, const unsigned char *key,
                         size_t key_len, hmc_data_type input_type,
                         const unsigned char *input, size_t input_len,
                         hmc_hash_type hash_type,
                         hmc_data_type output_type, unsigned char *output,
                         size_t output_max_len, size_t *output_len) {
  unsigned char *decoded_input = NULL;
  int wc_hash_type;
  size_t digest_size;
  switch (hash_type) {
  case HMC_HASH_TYPE_SHA256:
    wc_hash_type = WC_HASH_TYPE_SHA256;
    digest_size = SHA256_DIGEST_SIZE;
    break;
  case HMC_HASH_TYPE_SHA1:
    wc_hash_type = WC_HASH_TYPE_SHA;
    digest_size = SHA_DIGEST_SIZE;
    break;
  default:
    return HMC_STATUS_FAILURE;
  }
  if (input_type != HMC_DATA_TYPE_RAW) {
    size_t decoded_input_alloc = 4 * input_len;
    decoded_input = malloc(decoded_input_alloc);
    size_t decoded_input_len;
    hmc_status status = hmc_convert(input_type, HMC_CRED_TYPE_NONE, input, input_len, HMC_HASH_TYPE_NONE,
                         HMC_DATA_TYPE_RAW, decoded_input, decoded_input_alloc, &decoded_input_len);
    if (status != HMC_STATUS_OK) {
      free(decoded_input);
      return status;
    }
    input = decoded_input;
    input_len = decoded_input_len;
  }

  Hmac hmac;
  int rc;

  if (key_data_type == HMC_DATA_TYPE_RAW) {
    rc = wc_HmacSetKey(&hmac, wc_hash_type, key, key_len);
  } else {
    size_t key_output_len = 0;
    unsigned char key_output[KEY_DECODE_BUF_SIZE];
    hmc_status status = hmc_convert(key_data_type, HMC_CRED_TYPE_NONE, key, key_len, HMC_HASH_TYPE_NONE,
                                    HMC_DATA_TYPE_RAW, key_output, sizeof(key_output), &key_output_len);
    if (status != HMC_STATUS_OK) {
      free(decoded_input);
      return status;
    } else if (key_output_len != AES_KEY_SIZE) {
      free(decoded_input);
      return HMC_STATUS_INVALID_KEY_SIZE;
    }

    rc = wc_HmacSetKey(&hmac, wc_hash_type, key_output, key_output_len);
  }
  if (rc) {
    hml_error("wc_HmacSetKey key failed with %d", rc);
    free(decoded_input);
    return HMC_STATUS_FAILURE;
  }

  rc = wc_HmacUpdate(&hmac, input, input_len);
  if (rc) {
    hml_error("wc_HmacUpdate failed with %d", rc);
    free(decoded_input);
    return HMC_STATUS_FAILURE;
  }

  byte derived_key[SHA256_DIGEST_SIZE];
  rc = wc_HmacFinal(&hmac, derived_key);
  if (rc) {
    hml_error("wc_HmacFinal failed with %d", rc);
    free(decoded_input);
    return HMC_STATUS_FAILURE;
  }

  hmc_status status = hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, derived_key, digest_size,
                                  HMC_HASH_TYPE_NONE, output_type, output, output_max_len, output_len);
  free(decoded_input);
  return status;
}

hmc_status hmc_sha256_hmac_writer(hmc_data_type key_data_type, const unsigned char *key,
                                  size_t key_len, void **output_hmac) {
  unsigned char *decoded_key = NULL;

  if (key_data_type != HMC_DATA_TYPE_RAW) {
    size_t decoded_key_alloc = 4 * key_len;
    decoded_key = malloc(decoded_key_alloc);
    size_t decoded_key_len;
    hmc_status status = hmc_convert(key_data_type, HMC_CRED_TYPE_NONE, key, key_len, HMC_HASH_TYPE_NONE,
                                    HMC_DATA_TYPE_RAW, decoded_key, decoded_key_alloc, &decoded_key_len);
    if (status != HMC_STATUS_OK) {
      free(decoded_key);
      return status;
    }
    key = decoded_key;
    key_len = decoded_key_len;
  }

  Hmac *hmac = malloc(sizeof(Hmac));

  int rc = wc_HmacSetKey(hmac, WC_HASH_TYPE_SHA256, key, key_len);
  free(decoded_key);
  if (rc) {
    hml_error("wc_HmacSetKey key failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  *output_hmac = hmac;
  return HMC_STATUS_OK;
}

hmc_status hmc_update_hmac(void *hmac, const unsigned char *input, size_t input_len) {
  int rc = wc_HmacUpdate(hmac, input, input_len);
  if (rc) {
    hml_error("wc_HmacUpdate failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

hmc_status hmc_finalize_sha256_hmac(void *hmac, unsigned char out[SHA256_DIGEST_SIZE]) {
  int rc = wc_HmacFinal(hmac, out);
  if (rc) {
    hml_error("wc_HmacFinal failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

hmc_status hmc_free_hmac_writer(void *hmac) {
  free(hmac);
  return HMC_STATUS_OK;
}

hmc_status hmc_free(void *hmac) {
  free(hmac);
  return HMC_STATUS_OK;              
}                                    
                                     
hmc_status hmc_sha256_writer(void **output_hasher) {
  wc_Sha256 *hasher = malloc(sizeof(wc_Sha256));
  int rc = wc_InitSha256(hasher);    
  if (rc) {
    hml_error("wc_initSha256 failed with %d", rc);
    return HMC_STATUS_FAILURE;   
  }
  *output_hasher = hasher;       
  return HMC_STATUS_OK;          
}
                                 
hmc_status hmc_sha256_update(void *hasher, const unsigned char *input, size_t len) {
  if (len > UINT_MAX) {
    hml_error("hmc_sha256_update called with %ld bytes", len); 
    return HMC_STATUS_FAILURE;   
  }
                             
  int rc = wc_Sha256Update(hasher, input, len);
  if (rc) {                  
    hml_error("wc_Sha256Update failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;    
}
                                     
hmc_status hmc_sha256_gethash(void *hasher, unsigned char out[SHA256_DIGEST_SIZE]) {
  int rc = wc_Sha256GetHash(hasher, out);
  if (rc) {
    hml_error("wc_Sha256GetHash failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

hmc_status hmc_derive_key(hmc_data_type key_data_type, const unsigned char *key,
                          size_t key_len, hmc_data_type input_type,
                          const unsigned char *input, size_t input_len,
                          hmc_data_type output_type, unsigned char *output,
                          size_t output_max_len, size_t *output_len) {
  return hmc_hmac_sign(key_data_type, key, key_len, input_type, input, input_len,
                       HMC_HASH_TYPE_SHA256, output_type, output, output_max_len,
                       output_len);
}

hmc_status hmc_generate_key_pair(
    hmc_key_type key_type, hmc_data_type output_type,
    unsigned char *private_key_output, size_t private_key_output_max_len,
    size_t *private_key_output_len, unsigned char *public_key_output,
    size_t public_key_output_max_len, size_t *public_key_output_len) {

  switch (key_type) {
  case HMC_KEY_TYPE_ECC256:
  case HMC_KEY_TYPE_ECC384:
  case HMC_KEY_TYPE_ECC521:
    return hmc_generate_ecc_key_pair(
        key_type, output_type, private_key_output, private_key_output_max_len,
        private_key_output_len, public_key_output, public_key_output_max_len,
        public_key_output_len);
  case HMC_KEY_TYPE_KYBER512:
  case HMC_KEY_TYPE_KYBER768:
  case HMC_KEY_TYPE_KYBER1024:
    return hmc_generate_kyber_key_pair(
        key_type, output_type, private_key_output, private_key_output_max_len,
        private_key_output_len, public_key_output, public_key_output_max_len,
        public_key_output_len);
  case HMC_KEY_TYPE_RSA3072_E3:
    return hmc_generate_rsa_key_pair(
        key_type, output_type, private_key_output, private_key_output_max_len,
        private_key_output_len, public_key_output, public_key_output_max_len,
        public_key_output_len);
  default:
    hml_error("key type %d not supported", key_type);
    return HMC_STATUS_FAILURE;
  }
}

hmc_status hmc_create_shared_ecc_secret(
    hmc_key_type key_type, hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_data_type output_type, unsigned char *output, size_t output_max_len,
    size_t *output_len) {
  ecc_key pub;
  ecc_key priv;
  hmc_status status;
  int rc;
  WC_RNG rng;

  if ((key_type != HMC_KEY_TYPE_ECC256) &&
      (key_type != HMC_KEY_TYPE_ECC384) &&
      (key_type != HMC_KEY_TYPE_ECC521)) {
    hml_error("key type %d not supported", key_type);
    return HMC_STATUS_FAILURE;
  }

  if (key_data_type == HMC_DATA_TYPE_RAW) {
    key_data_type = HMC_DATA_TYPE_DER;
  }

  status =
      hmc_read_public_ecc_key(key_data_type, public_key, public_key_len, &pub);
  if (status != HMC_STATUS_OK) {
    return status;
  }
  status = hmc_read_private_ecc_key(key_data_type, private_key, private_key_len,
                                    &priv);
  if (status != HMC_STATUS_OK) {
    wc_ecc_free(&pub);
    return status;
  }

  rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    wc_ecc_free(&pub);
    return HMC_STATUS_FAILURE;
  }

  unsigned char secret_buf[MAX_SECRET_SIZE];
  word32 secret_len = sizeof(secret_buf);
  rc = wc_ecc_set_rng(&priv, &rng);
  if (rc) {
    hml_error("set key rng failed with %d", rc);
    wc_FreeRng(&rng);
    wc_ecc_free(&pub);
    wc_ecc_free(&priv);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_ecc_set_rng(&pub, &rng);
  if (rc) {
    hml_error("set key rng failed with %d", rc);
    wc_FreeRng(&rng);
    wc_ecc_free(&pub);
    wc_ecc_free(&priv);
    return HMC_STATUS_FAILURE;
  }

  rc = wc_ecc_shared_secret(&priv, &pub, secret_buf, &secret_len);
  wc_ecc_free(&pub);
  wc_ecc_free(&priv);
  if (rc) {
    hml_error("generate shared key failed with %d", rc);
    wc_FreeRng(&rng);
    return HMC_STATUS_FAILURE;
  }

  wc_FreeRng(&rng);

  return hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, secret_buf, secret_len,
                     HMC_HASH_TYPE_NONE, output_type, output, output_max_len,
                     output_len);
}

hmc_status hmc_create_shared_ecc_kyber_hybrid_secret(
    hmc_key_type ecc_key_type, hmc_data_type ecc_key_data_type,
    const unsigned char *ecc_private_key, size_t ecc_private_key_len,
    const unsigned char *ecc_public_key, size_t ecc_public_key_len,
    hmc_data_type kyber_shared_secret_input_type,
    unsigned char *kyber_shared_secret, size_t kyber_shared_secret_len,
    hmc_data_type output_type, unsigned char *output, size_t output_max_len,
    size_t *output_len) {
#ifndef NO_KYBER
  hmc_status status;

  unsigned char ecc_shared_secret[MAX_SECRET_SIZE];
  size_t ecc_shared_secret_len;
  status = hmc_create_shared_ecc_secret(
      ecc_key_type, ecc_key_data_type, ecc_private_key, ecc_private_key_len,
      ecc_public_key, ecc_public_key_len, HMC_DATA_TYPE_RAW, ecc_shared_secret,
      sizeof(ecc_shared_secret), &ecc_shared_secret_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  unsigned char kyber_secret[KYBER_SS_SZ];
  size_t kyber_secret_len;
  status = hmc_convert(kyber_shared_secret_input_type, HMC_CRED_TYPE_NONE,
                       kyber_shared_secret, kyber_shared_secret_len,
                       HMC_HASH_TYPE_NONE, HMC_DATA_TYPE_RAW, kyber_secret,
                       sizeof(kyber_secret), &kyber_secret_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  unsigned char combined_key[ecc_shared_secret_len + kyber_secret_len];
  memcpy(combined_key, ecc_shared_secret, ecc_shared_secret_len);
  memcpy(combined_key + ecc_shared_secret_len, kyber_secret, kyber_secret_len);

  unsigned char hashed_secret[SHA256_SIZE];
  status = hmc_sha256(combined_key, sizeof(combined_key), hashed_secret);
  if (status != HMC_STATUS_OK) {
    hml_error("Could not hash data");
    return status;
  }
  return hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, hashed_secret,
                     sizeof(hashed_secret), HMC_HASH_TYPE_NONE, output_type,
                     output, output_max_len, output_len);
#else
  return HMC_STATUS_FAILURE;
#endif
}

hmc_status hmc_create_shared_kyber_secret(
    hmc_key_type key_type, hmc_data_type key_data_type,
    const unsigned char *public_key, size_t public_key_len,
    hmc_data_type output_type, unsigned char *output_secret,
    size_t output_secret_max_len, size_t *output_secret_len,
    unsigned char *output_encrypted_secret,
    size_t output_encrypted_secret_max_len,
    size_t *output_encrypted_secret_len) {
#ifndef NO_KYBER
  KyberKey key;
  hmc_status status;
  WC_RNG rng;
  size_t pub_len;
  size_t cipher_text_len;
  size_t shared_secret_len;
  int type;
  int rc;

  switch (key_type) {
  case HMC_KEY_TYPE_KYBER512:
    pub_len = KYBER512_PUBLIC_KEY_SIZE;
    cipher_text_len = KYBER512_CIPHER_TEXT_SIZE;
    type = KYBER512;
    break;
  case HMC_KEY_TYPE_KYBER768:
    pub_len = KYBER768_PUBLIC_KEY_SIZE;
    cipher_text_len = KYBER768_CIPHER_TEXT_SIZE;
    type = KYBER768;
    break;
  case HMC_KEY_TYPE_KYBER1024:
    pub_len = KYBER1024_PUBLIC_KEY_SIZE;
    cipher_text_len = KYBER1024_CIPHER_TEXT_SIZE;
    type = KYBER1024;
    break;
  default:
    return HMC_STATUS_FAILURE;
  }

  unsigned char pub[pub_len];
  size_t pub_out_len;
  status = hmc_convert(key_data_type, HMC_CRED_TYPE_NONE, public_key, public_key_len,
                       HMC_HASH_TYPE_NONE, HMC_DATA_TYPE_RAW, pub, sizeof(pub),
                       &pub_out_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  shared_secret_len = KYBER_SS_SZ;
  rc = wc_KyberKey_Init(type, &key, NULL, INVALID_DEVID);
  if (rc) {
    hml_error("key init failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    wc_KyberKey_Free(&key);
    return HMC_STATUS_FAILURE;
  }

  rc = wc_KyberKey_DecodePublicKey(&key, pub, pub_len);
  if (rc) {
    hml_error("decode public key failed with %d", rc);
    wc_FreeRng(&rng);
    wc_KyberKey_Free(&key);
    return HMC_STATUS_FAILURE;
  }

  unsigned char shared_secret[shared_secret_len];
  unsigned char cipher_text[cipher_text_len];

  rc = wc_KyberKey_Encapsulate(&key, cipher_text, shared_secret, &rng);
  wc_FreeRng(&rng);
  wc_KyberKey_Free(&key);

  if (rc) {
    hml_error("encapsulate failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  status = hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, shared_secret,
                       shared_secret_len, HMC_HASH_TYPE_NONE, output_type,
                       output_secret, output_secret_max_len, output_secret_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }
  return hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, cipher_text, cipher_text_len,
                     HMC_HASH_TYPE_NONE, output_type, output_encrypted_secret,
                     output_encrypted_secret_max_len,
                     output_encrypted_secret_len);
#else
  return HMC_STATUS_FAILURE;
#endif
}

hmc_status hmc_decrypt_shared_kyber_secret(
    hmc_key_type key_type, hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    hmc_data_type encrypted_secret_data_type,
    const unsigned char *encrypted_secret, size_t encrypted_secret_len,
    hmc_data_type output_type, unsigned char *output, size_t output_max_len,
    size_t *output_len) {
#ifndef NO_KYBER
  KyberKey key;
  hmc_status status;
  size_t priv_len;
  size_t shared_secret_len;
  size_t cipher_text_len;
  int type;
  int rc;

  switch (key_type) {
  case HMC_KEY_TYPE_KYBER512:
    priv_len = KYBER512_PRIVATE_KEY_SIZE;
    cipher_text_len = KYBER512_CIPHER_TEXT_SIZE;
    type = KYBER512;
    break;
  case HMC_KEY_TYPE_KYBER768:
    priv_len = KYBER768_PRIVATE_KEY_SIZE;
    cipher_text_len = KYBER768_CIPHER_TEXT_SIZE;
    type = KYBER768;
    break;
  case HMC_KEY_TYPE_KYBER1024:
    priv_len = KYBER1024_PRIVATE_KEY_SIZE;
    cipher_text_len = KYBER1024_CIPHER_TEXT_SIZE;
    type = KYBER1024;
    break;
  default:
    return HMC_STATUS_FAILURE;
  }

  unsigned char priv[priv_len];
  size_t priv_out_len;
  status = hmc_convert(key_data_type, HMC_CRED_TYPE_NONE, private_key, private_key_len,
                       HMC_HASH_TYPE_NONE, HMC_DATA_TYPE_RAW, priv,
                       sizeof(priv), &priv_out_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  unsigned char cipher_text[cipher_text_len];
  size_t cipher_text_out_len;
  status =
      hmc_convert(encrypted_secret_data_type, HMC_CRED_TYPE_NONE, encrypted_secret,
                  encrypted_secret_len, HMC_HASH_TYPE_NONE, HMC_DATA_TYPE_RAW,
                  cipher_text, sizeof(cipher_text), &cipher_text_out_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  shared_secret_len = KYBER_SS_SZ;
  rc = wc_KyberKey_Init(type, &key, NULL, INVALID_DEVID);
  if (rc) {
    hml_error("key init failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  rc = wc_KyberKey_DecodePrivateKey(&key, priv, priv_len);
  if (rc) {
    hml_error("decode private key failed with %d", rc);
    wc_KyberKey_Free(&key);
    return HMC_STATUS_FAILURE;
  }

  unsigned char shared_secret[shared_secret_len];

  rc = wc_KyberKey_Decapsulate(&key, shared_secret, cipher_text,
                               cipher_text_out_len);
  wc_KyberKey_Free(&key);

  if (rc) {
    hml_error("decapsulate failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  return hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, shared_secret, shared_secret_len,
                     HMC_HASH_TYPE_NONE, output_type, output, output_max_len,
                     output_len);
#else
  return HMC_STATUS_FAILURE;
#endif
}

hmc_status
hmc_create_signature(hmc_key_type key_type, hmc_cred_type cred_type, hmc_data_type key_data_type,
                     const unsigned char *private_key, size_t private_key_len,
                     const unsigned char *input, size_t input_len,
                     hmc_data_type output_type, unsigned char *output,
                     size_t output_max_len, size_t *output_len) {
  switch (key_type) {
  case HMC_KEY_TYPE_ECC256:
  case HMC_KEY_TYPE_ECC384:
  case HMC_KEY_TYPE_ECC521:
    if (cred_type != HMC_CRED_TYPE_PRIVATE_KEY) {
       hml_error("invalid cred type");
       return HMC_STATUS_FAILURE;
    }
    return hmc_create_ecc_signature(
        key_type, key_data_type, private_key, private_key_len, input, input_len,
        output_type, output, output_max_len, output_len);
  case HMC_KEY_TYPE_RSA:
    return hmc_create_rsa_signature(
        key_type, cred_type, key_data_type, private_key, private_key_len, input, input_len,
        output_type, output, output_max_len, output_len);
  default:
    hml_error("key type %d not supported", key_type);
    return HMC_STATUS_FAILURE;
  }
}

//  __year_to_secs from musl/src/time/__year_to_secs.c
static long long __year_to_secs(long long year, int *is_leap)
{
	if (year-2ULL <= 136) {
		int y = year;
		int leaps = (y-68)>>2;
		if (!((y-68)&3)) {
			leaps--;
			if (is_leap) *is_leap = 1;
		} else if (is_leap) *is_leap = 0;
		return 31536000*(y-70) + 86400*leaps;
	}

	int cycles, centuries, leaps, rem;

	if (!is_leap) is_leap = &(int){0};
	cycles = (year-100) / 400;
	rem = (year-100) % 400;
	if (rem < 0) {
		cycles--;
		rem += 400;
	}
	if (!rem) {
		*is_leap = 1;
		centuries = 0;
		leaps = 0;
	} else {
		if (rem >= 200) {
			if (rem >= 300) centuries = 3, rem -= 300;
			else centuries = 2, rem -= 200;
		} else {
			if (rem >= 100) centuries = 1, rem -= 100;
			else centuries = 0;
		}
		if (!rem) {
			*is_leap = 0;
			leaps = 0;
		} else {
			leaps = rem / 4U;
			rem %= 4U;
			*is_leap = !rem;
		}
	}

	leaps += 97*cycles + 24*centuries - *is_leap;

	return (year-100) * 31536000LL + leaps * 86400LL + 946684800 + 86400;
}


//  __month_to_secs from musl/src/time/__month_to_secs.c
static int __month_to_secs(int month, int is_leap)
{
	static const int secs_through_month[] = {
		0, 31*86400, 59*86400, 90*86400,
		120*86400, 151*86400, 181*86400, 212*86400,
		243*86400, 273*86400, 304*86400, 334*86400 };
	int t = secs_through_month[month];
	if (is_leap && month >= 2) t+=86400;
	return t;
}


//  __tm_to_secs from musl/src/time/__tm_to_secs.c
static long long __tm_to_secs(const struct tm *tm)
{
	int is_leap;
	long long year = tm->tm_year;
	int month = tm->tm_mon;
	if (month >= 12 || month < 0) {
		int adj = month / 12;
		month %= 12;
		if (month < 0) {
			adj--;
			month += 12;
		}
		year += adj;
	}
	long long t = __year_to_secs(year, &is_leap);
	t += __month_to_secs(month, is_leap);
	t += 86400LL * (tm->tm_mday-1);
	t += 3600LL * tm->tm_hour;
	t += 60LL * tm->tm_min;
	t += tm->tm_sec;
	return t;
}

hmc_status hmc_certificate_status(const unsigned char *cert,
                                size_t cert_len,
                                hmc_data_type cert_data_type,
                                hmc_cert_status *cert_status,
                                hmc_key_type *key_type,
                                long long *not_before,
                                long long *not_after,
                                unsigned char *is_ca) {

  DecodedCert decodedCert;
  size_t decode_cert_len;
  unsigned char decode_cert[cert_len * 4];
  const unsigned char *decode_cert_ptr = decode_cert;
  int rc = 0;

  *cert_status = HMC_CERT_STATUS_INVALID;

  if (cert_data_type == HMC_DATA_TYPE_DER) {
    decode_cert_len = cert_len;
    decode_cert_ptr = cert;
  } else if (cert_data_type == HMC_DATA_TYPE_PEM) {
    rc = wc_CertPemToDer(cert, cert_len, decode_cert,
      sizeof(decode_cert), CERT_TYPE);
    if (rc <= 0) {
      hml_error("pem to der failed with %d", rc);
      return HMC_STATUS_FAILURE;
    }
    decode_cert_len = rc;
  } else {
    hml_error("cert data type must be DER or PEM");
    return HMC_STATUS_FAILURE;
  }
  wc_InitDecodedCert(&decodedCert, decode_cert_ptr, decode_cert_len, NULL);
  // TODO: create a certificate manager and use it to verify the certificate
  rc = wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);

  /**
   * wc_ParseCert returns success or an error code. It will also
   * set the decodedCert.selfSigned and decodedCert.badDate field
   * if the certificate is self-signed or expired.
   *
   * We want to answer the following yes/no questions:
   * 1. Is the certificate self-signed?
   * 2. Is the certificate expired?
   * 3. Is the certificate chain verified? (not implemented yet)
   *
   * Below we test all possible combinations of
   * (rc, selfSigned, badDate) that are relevant to answering
   * those questions.
  */
  if (rc == 0) {
    if (decodedCert.selfSigned && decodedCert.badDate) {
      *cert_status = HMC_CERT_STATUS_EXPIRED_AND_SELF_SIGNED;
    } else if (decodedCert.selfSigned) {
      *cert_status = HMC_CERT_STATUS_SELF_SIGNED;
    } else if (decodedCert.badDate) {
      *cert_status = HMC_CERT_STATUS_EXPIRED;
    } else {
      *cert_status = HMC_CERT_STATUS_OK;
    }
  } else if ((rc == ASN_BEFORE_DATE_E) || (rc == ASN_AFTER_DATE_E)) {
    if (decodedCert.selfSigned) {
      *cert_status = HMC_CERT_STATUS_EXPIRED_AND_SELF_SIGNED;
    } else {
      *cert_status = HMC_CERT_STATUS_EXPIRED;
    }
  } else if ((rc == ASN_SELF_SIGNED_E) || ((rc == ASN_NO_SIGNER_E) && decodedCert.selfSigned)) {
    if (decodedCert.badDate) {
      *cert_status = HMC_CERT_STATUS_EXPIRED_AND_SELF_SIGNED;
    } else {
      *cert_status = HMC_CERT_STATUS_SELF_SIGNED;
    }
  } else {
      hml_error("wc_ParseCert failed with %d", rc);
      return HMC_STATUS_FAILURE;
  }

  switch (decodedCert.keyOID) {
  case RSAk:
    *key_type = HMC_KEY_TYPE_RSA;
    break;
  case ECDSAk:
    switch (decodedCert.pubKeySize) {
      case 91:
        *key_type = HMC_KEY_TYPE_ECC256;
        break;
      case 120:
        *key_type = HMC_KEY_TYPE_ECC384;
        break;
      case 158:
        *key_type = HMC_KEY_TYPE_ECC521;
        break;
      default:
        hml_error("key size %d not recognized", decodedCert.pubKeySize);
        return HMC_STATUS_FAILURE;
    }
    break;
  default:
    hml_error("keyOID %d not recognized", decodedCert.keyOID);
      return HMC_STATUS_FAILURE;
  }

  const byte* date;
  byte format;
  int length;
  struct tm temp;

  rc = wc_GetDateInfo(decodedCert.beforeDate, decodedCert.beforeDateLen, &date,
    &format, &length);
  if (rc) {
    hml_error("wc_GetDateInfo failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_GetDateAsCalendarTime(date, length, format, &temp);
  if (rc) {
    hml_error("wc_GetDateAsCalendarTime failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  *not_before = __tm_to_secs(&temp);

  rc = wc_GetDateInfo(decodedCert.afterDate, decodedCert.afterDateLen, &date,
    &format, &length);
  if (rc) {
    hml_error("wc_GetDateInfo failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_GetDateAsCalendarTime(date, length, format, &temp);
  if (rc) {
    hml_error("wc_GetDateAsCalendarTime failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  *not_after = __tm_to_secs(&temp);

  *is_ca = decodedCert.isCA;

  return HMC_STATUS_OK;
}

hmc_status hmc_extract_public_key(const unsigned char *cert,
                                size_t cert_len,
                                hmc_data_type cert_data_type,
                                hmc_data_type output_type,
                                unsigned char *output,
                                size_t output_max_len, size_t *output_len) {
  DecodedCert decodedCert;
  size_t decode_cert_len;
  word32 der_key_size;
  unsigned char decode_cert[cert_len * 4];
  unsigned char der_key[output_max_len];
  const unsigned char *decode_cert_ptr = decode_cert;
  int rc = 0;

  if (cert_data_type == HMC_DATA_TYPE_DER) {
    decode_cert_len = cert_len;
    decode_cert_ptr = cert;
  } else if (cert_data_type == HMC_DATA_TYPE_PEM) {
    rc = wc_CertPemToDer(cert, cert_len, decode_cert,
      sizeof(decode_cert), CERT_TYPE);
    if (rc <= 0) {
      hml_error("pem to der failed with %d", rc);
      return HMC_STATUS_FAILURE;
    }
    decode_cert_len = rc;
  } else {
    hml_error("cert data type must be DER or PEM");
    return HMC_STATUS_FAILURE;
  }
  wc_InitDecodedCert(&decodedCert, decode_cert_ptr, decode_cert_len, NULL);
  rc = wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
  if (rc) {
    hml_error("parse cert failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  der_key_size = sizeof(der_key);
  rc = wc_GetPubKeyDerFromCert(&decodedCert, der_key, &der_key_size);
  if (rc < 0) {
    hml_error("get pub key der from cert failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  if (output_type == HMC_DATA_TYPE_DER) {
    memcpy(output, der_key, der_key_size);
    return HMC_STATUS_OK;
  } else if (output_type == HMC_DATA_TYPE_PEM) {
    return hmc_convert(HMC_DATA_TYPE_DER, HMC_CRED_TYPE_PUBLIC_KEY, der_key, der_key_size,
                       HMC_HASH_TYPE_NONE, HMC_DATA_TYPE_PEM, output, output_max_len,
                       output_len);
  } else {
    hml_error("output key data type must be DER or PEM");
    return HMC_STATUS_FAILURE;
  }
}

hmc_status hmc_verify_signature(hmc_key_type key_type,
                                hmc_data_type key_data_type,
                                const unsigned char *public_key,
                                size_t public_key_len,
                                const unsigned char *input, size_t input_len,
                                hmc_sig_format signature_format,
                                hmc_data_type signature_data_type,
                                const unsigned char *signature,
                                size_t signature_len, bool *verified) {
  switch (key_type) {
  case HMC_KEY_TYPE_ECC256:
  case HMC_KEY_TYPE_ECC384:
  case HMC_KEY_TYPE_ECC521:
    break;
  default:
    hml_error("key type %d not supported", key_type);
    return HMC_STATUS_FAILURE;
  }
  return hmc_verify_ecc_signature(
      key_type, key_data_type, public_key, public_key_len, input, input_len,
      signature_format, signature_data_type, signature, signature_len, verified);
}

hmc_status hmc_create_root_certificate(
    const char *common_name, size_t common_name_len,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type, hmc_data_type output_data_type,
    unsigned char *output, size_t output_max_len, size_t *output_len
) {
  return hmc_create_self_signed_ecc_certificate(
    common_name, common_name_len,
    1, 365, 1,
    key_data_type,
    private_key, private_key_len,
    public_key, public_key_len,
    output_sig_type, output_data_type, output,
    output_max_len, output_len
  );
}

hmc_status hmc_create_self_signed_certificate(
    const char *common_name, size_t common_name_len,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type, hmc_data_type output_data_type,
    unsigned char *output, size_t output_max_len, size_t *output_len
) {
  return hmc_create_self_signed_ecc_certificate(
    common_name, common_name_len,
    0, 30, 0,
    key_data_type,
    private_key, private_key_len,
    public_key, public_key_len,
    output_sig_type, output_data_type, output,
    output_max_len, output_len
  );
}

hmc_status hmc_create_certificate(
    const unsigned char *csr, size_t csr_len, hmc_data_type csr_data_type,
    const unsigned char *ca_cert, size_t ca_cert_len,
    hmc_data_type ca_cert_data_type,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type,
    hmc_data_type output_data_type, unsigned char *output,
    size_t output_max_len, size_t *output_len) {
    return hmc_create_certificate_internal(csr, csr_len, csr_data_type,
      0, 30, 0,
      ca_cert, ca_cert_len, ca_cert_data_type,
      key_data_type,
      private_key, private_key_len,
      public_key, public_key_len,
      output_sig_type, output_data_type, output, output_max_len, output_len);
}

hmc_status hmc_create_intermediate_certificate(
    const unsigned char *csr, size_t csr_len, hmc_data_type csr_data_type,
    const unsigned char *ca_cert, size_t ca_cert_len,
    hmc_data_type ca_cert_data_type,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type,
    hmc_data_type output_data_type, unsigned char *output,
    size_t output_max_len, size_t *output_len) {
    return hmc_create_certificate_internal(csr, csr_len, csr_data_type,
      1, 30, 0,
      ca_cert, ca_cert_len, ca_cert_data_type,
      key_data_type,
      private_key, private_key_len,
      public_key, public_key_len,
      output_sig_type, output_data_type, output, output_max_len, output_len);
}

static hmc_status hmc_create_certificate_internal(
    const unsigned char *csr, size_t csr_len, hmc_data_type csr_data_type,
    int is_intermediate_CA, int days_valid, unsigned char path_length,
    const unsigned char *ca_cert, size_t ca_cert_len,
    hmc_data_type ca_cert_data_type,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type,
    hmc_data_type output_data_type, unsigned char *output,
    size_t output_max_len, size_t *output_len) {
  if (csr_len == 0) {
    hml_error("csr is empty");
    return HMC_STATUS_FAILURE;
  } else if (csr_len >= MAX_CERT_SIZE) {
    hml_error("csr too long");
    return HMC_STATUS_FAILURE;
  }
  if (!((output_sig_type == HMC_SIG_TYPE_CTC_SHA256wECDSA) ||
       (output_sig_type == HMC_SIG_TYPE_CTC_SHA384wECDSA) ||
       (output_sig_type == HMC_SIG_TYPE_CTC_SHA512wECDSA))) {
    hml_error("signature type %d not supported", output_sig_type);
    return HMC_STATUS_FAILURE;
  }
  if (csr_data_type == HMC_DATA_TYPE_RAW) {
    csr_data_type = HMC_DATA_TYPE_DER;
  }
  if (ca_cert_data_type == HMC_DATA_TYPE_RAW) {
    ca_cert_data_type = HMC_DATA_TYPE_DER;
  }
  if (output_data_type == HMC_DATA_TYPE_RAW) {
    output_data_type = HMC_DATA_TYPE_DER;
  }
  if ((csr_data_type != HMC_DATA_TYPE_PEM) &&
      (csr_data_type != HMC_DATA_TYPE_DER)) {
    hml_error("csr data type not supported");
    return HMC_STATUS_FAILURE;
  }
  if ((ca_cert_data_type != HMC_DATA_TYPE_PEM) &&
      (ca_cert_data_type != HMC_DATA_TYPE_DER)) {
    hml_error("ca cert data type not supported");
    return HMC_STATUS_FAILURE;
  }
  if ((output_data_type != HMC_DATA_TYPE_PEM) &&
      (output_data_type != HMC_DATA_TYPE_DER)) {
    hml_error("output cert data type not supported");
    return HMC_STATUS_FAILURE;
  }
  return hmc_create_ecc_certificate_internal(
      csr, csr_len, csr_data_type,
      is_intermediate_CA, days_valid, path_length,
      ca_cert, ca_cert_len, ca_cert_data_type,
      key_data_type,
      private_key, private_key_len,
      public_key, public_key_len,
      output_sig_type,
      output_data_type, output, output_max_len, output_len);
}

hmc_status hmc_create_certificate_signing_request(
  const char *common_name, size_t common_name_len,
  hmc_key_type key_type, hmc_data_type key_data_type,
  const unsigned char *private_key, size_t private_key_len,
  hmc_sig_type output_sig_type,
  hmc_data_type output_data_type, unsigned char *output,
  size_t output_max_len, size_t *output_len
) {
  if (common_name_len == 0) {
    hml_error("common name is empty");
    return HMC_STATUS_FAILURE;
  } else if (common_name_len >= MAX_NAME_SIZE) {
    hml_error("common name too long");
    return HMC_STATUS_FAILURE;
  }
  if (!((key_type == HMC_KEY_TYPE_ECC256) ||
       (key_type == HMC_KEY_TYPE_ECC384) ||
       (key_type == HMC_KEY_TYPE_ECC521))) {
    hml_error("key type %d not supported", key_type);
    return HMC_STATUS_FAILURE;
  }
  if (!((output_sig_type == HMC_SIG_TYPE_CTC_SHA256wECDSA) ||
       (output_sig_type == HMC_SIG_TYPE_CTC_SHA384wECDSA) ||
       (output_sig_type == HMC_SIG_TYPE_CTC_SHA512wECDSA))) {
    hml_error("signature type %d not supported", output_sig_type);
    return HMC_STATUS_FAILURE;
  }

  if (key_data_type == HMC_DATA_TYPE_RAW) {
    key_data_type = HMC_DATA_TYPE_DER;
  }
  if (output_data_type == HMC_DATA_TYPE_RAW) {
    output_data_type = HMC_DATA_TYPE_DER;
  }
  if ((key_data_type != HMC_DATA_TYPE_PEM) &&
      (key_data_type != HMC_DATA_TYPE_DER)) {
    hml_error("input csr key data type not supported");
    return HMC_STATUS_FAILURE;
  }
  if ((output_data_type != HMC_DATA_TYPE_PEM) &&
      (output_data_type != HMC_DATA_TYPE_DER)) {
    hml_error("output csr data type not supported");
    return HMC_STATUS_FAILURE;
  }
  switch (key_type) {
  case HMC_KEY_TYPE_ECC256:
  case HMC_KEY_TYPE_ECC384:
  case HMC_KEY_TYPE_ECC521:
    return hmc_create_ecc_certificate_signing_request(
      common_name, common_name_len,
      key_type, key_data_type,
      private_key, private_key_len,
      output_sig_type,
      output_data_type, output,
      output_max_len, output_len
    );
  default:
    hml_error("csr generation key type %d not supported", key_type);
    return HMC_STATUS_FAILURE;
  }
}

hmc_status hmc_ecc_key_to_pkcs8(hmc_data_type key_data_type,
                                const unsigned char *private_key, size_t private_key_len,
                                hmc_data_type output_data_type,
                                unsigned char *output, size_t output_max_len, size_t *output_len) {
  ecc_key key;
  word32 curve_oid_sz = 0;
  const byte *curve_oid = NULL;
  word32 out_sz;
  size_t der_len;
  int status;

  status = hmc_read_private_ecc_key(key_data_type, private_key, private_key_len, &key);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  status = wc_ecc_make_pub(&key, NULL);
  if (status) {
    wc_ecc_free(&key);
    hml_error("make pub key failed with %d", status);
    return HMC_STATUS_FAILURE;
  }

  word32 ecc_derkey_len = private_key_len * 4;
  unsigned char* ecc_derkey = malloc(ecc_derkey_len);

  status = wc_EccKeyToDer(&key, ecc_derkey, ecc_derkey_len);
  if (status < 0) {
    wc_ecc_free(&key);
    free(ecc_derkey);
    hml_error("build der failed with %d", status);
    return HMC_STATUS_FAILURE;
  }
  der_len = status;

  status = wc_ecc_get_oid(key.dp->oidSum, &curve_oid, &curve_oid_sz);
  status = wc_CreatePKCS8Key(NULL, &out_sz, (byte *) ecc_derkey, der_len,
                  ECDSAk, curve_oid, curve_oid_sz);
  if ((status < 0) && (status != LENGTH_ONLY_E)) {
    wc_ecc_free(&key);
    free(ecc_derkey);
    hml_error("create pcks8 failed with %d", status);
    return HMC_STATUS_FAILURE;
  }
  unsigned char* output_der = malloc(out_sz);
  status = wc_CreatePKCS8Key(output_der, &out_sz, (byte *) ecc_derkey, der_len,
                  ECDSAk, curve_oid, curve_oid_sz);
  wc_ecc_free(&key);
  free(ecc_derkey);
  if (status < 0) {
    free(output_der);
    hml_error("create pcks8 failed with %d", status);
    return HMC_STATUS_FAILURE;
  }
  status = hmc_convert(HMC_DATA_TYPE_DER, HMC_CRED_TYPE_PKCS8, output_der, out_sz,
    HMC_HASH_TYPE_NONE, output_data_type, output, output_max_len, output_len);
  free(output_der);
  return status;
}

hmc_status hmc_import_ecc_key_x_y_d(hmc_key_type key_type,
                                const unsigned char *x, size_t x_len,
                                const unsigned char *y, size_t y_len,
                                const unsigned char *d, size_t d_len,
                                hmc_data_type output_type,
                                unsigned char *output, size_t output_max_len,
                                size_t *output_len) {
  ecc_key key;
  int curve_id = 0;
  size_t len = 0;
  int status;
  hmc_cred_type cred_type;

  if (output_type == HMC_DATA_TYPE_RAW) {
    output_type = HMC_DATA_TYPE_DER;
  }
  if ((output_type != HMC_DATA_TYPE_DER) && (output_type != HMC_DATA_TYPE_PEM)) {
    hml_error("output type %d not supported", output_type);
    return HMC_STATUS_FAILURE;
  }
  switch (key_type) {
  case HMC_KEY_TYPE_ECC256:
    curve_id = ECC_SECP256R1;
    len = 32;
    break;
  case HMC_KEY_TYPE_ECC384:
    curve_id = ECC_SECP384R1;
    len = 48;
    break;
  case HMC_KEY_TYPE_ECC521:
    curve_id = ECC_SECP521R1;
    len = 66;
    break;
  default:
    hml_error("key type %d not supported", key_type);
    return HMC_STATUS_FAILURE;
  }

  if ((x_len != len) || (y_len != len)) {
    hml_error("x and y must be %zu bytes", len);
    return HMC_STATUS_FAILURE;
  }
  if ((d == NULL) && (d_len == 0)) {
    cred_type = HMC_CRED_TYPE_PUBLIC_KEY;
  } else if ((d != NULL) && (d_len == len)) {
    cred_type = HMC_CRED_TYPE_PRIVATE_KEY;
  } else {
    hml_error("d must be %zu bytes or NULL", len);
    return HMC_STATUS_FAILURE;
  }

  wc_ecc_init(&key);
  status = wc_ecc_import_unsigned(&key, x, y, d, curve_id);
  if (status != HMC_STATUS_OK) {
    hml_error("could not import x and y coordinates to key %d", status);
    return status;
  }

  if (output_type == HMC_DATA_TYPE_DER) {
    int rc;
    if (cred_type == HMC_CRED_TYPE_PUBLIC_KEY) {
      rc = wc_EccPublicKeyToDer(&key, output, output_max_len, 1);
    } else {
      rc = wc_EccKeyToDer(&key, output, output_max_len);
    }
    if (rc < 0) {
      hml_error("could not convert public ecc key to der %d", rc);
      return HMC_STATUS_FAILURE;
    }
    *output_len = rc;
    return HMC_STATUS_OK;
  } else {
    int rc;
    word32 der_buffer_len = output_max_len;
    unsigned char *der_buffer = malloc(der_buffer_len);
    if (cred_type == HMC_CRED_TYPE_PUBLIC_KEY) {
      rc = wc_EccPublicKeyToDer(&key, der_buffer, der_buffer_len, 1);
    } else {
      rc = wc_EccKeyToDer(&key, der_buffer, der_buffer_len);
    }
    if (rc < 0) {
      free(der_buffer);
      hml_error("could not convert public ecc key to der %d", rc);
      return HMC_STATUS_FAILURE;
    }
    status = hmc_convert(HMC_DATA_TYPE_DER, cred_type, der_buffer, rc,
     HMC_HASH_TYPE_NONE, output_type, output, output_max_len, output_len);
    free(der_buffer);
    return status;
  }
}

hmc_status hmc_export_ecc_key_x_y(hmc_data_type key_data_type,
                                const unsigned char *public_key, size_t public_key_len,
                                const unsigned char *x, size_t x_max_len, size_t *x_len,
                                const unsigned char *y, size_t y_max_len, size_t *y_len) {
  ecc_key pub;

  int status = hmc_read_public_ecc_key(key_data_type, public_key, public_key_len, &pub);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  word32 x_len_val = x_max_len;
  word32 y_len_val = y_max_len;
  status = wc_ecc_export_public_raw(&pub, (byte *) x, &x_len_val, (byte *) y, &y_len_val);
  if (status != 0) {
    hml_error("could not export public ecc key");
    wc_ecc_free(&pub);
    return HMC_STATUS_FAILURE;
  }
  *x_len = x_len_val;
  *y_len = y_len_val;
  wc_ecc_free(&pub);
  return HMC_STATUS_OK;
}

hmc_status hmc_export_rsa_key_e_n(hmc_data_type key_data_type,
                                  const unsigned char *public_key, size_t public_key_len,
                                  const unsigned char *e, size_t e_max_len, size_t *e_len,
                                  const unsigned char *n, size_t n_max_len, size_t *n_len) {
  RsaKey pub;
  int status = hmc_read_public_rsa_key(key_data_type, public_key, public_key_len, &pub);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  word32 e_len_val = e_max_len;
  word32 n_len_val = n_max_len;

  status = wc_RsaFlattenPublicKey(&pub, (byte *) e, &e_len_val, (byte *) n, &n_len_val);
  if (status != 0) {
    hml_error("could not export public rsa key");
    wc_FreeRsaKey(&pub);
    return HMC_STATUS_FAILURE;
  }
  *e_len = e_len_val;
  *n_len = n_len_val;
  wc_FreeRsaKey(&pub);
  return HMC_STATUS_OK;
}

hmc_status hmc_convert(hmc_data_type input_type, hmc_cred_type input_cred_type,
                       const unsigned char *input, size_t input_len,
                       hmc_hash_type hash_type, hmc_data_type output_type,
                       unsigned char *output, size_t output_max_len,
                       size_t *output_len) {

  // (PEM to DER) and (DER to PEM) conversion must have a hmc_cred_type that is not HMC_CRED_TYPE_NONE
  // If we are not performing a conversion, then the hmc_cred_type is ignored
  if (((input_type == HMC_DATA_TYPE_PEM) || (input_type == HMC_DATA_TYPE_DER)) &&
      (input_cred_type == HMC_CRED_TYPE_NONE)) {
        hml_error("hmc_cred_type must be specified for PEM and DER conversions");
        return HMC_STATUS_FAILURE;
  }
  if (((input_type != HMC_DATA_TYPE_PEM) && (input_type != HMC_DATA_TYPE_DER)) &&
      (input_cred_type != HMC_CRED_TYPE_NONE)) {
        hml_error("hmc_cred_type must be HMC_CRED_TYPE_NONE for non PEM and DER conversions");
        return HMC_STATUS_FAILURE;
  }
  if (((input_type == HMC_DATA_TYPE_PEM) || (input_type == HMC_DATA_TYPE_DER)) &&
      ((output_type != HMC_DATA_TYPE_PEM) && (output_type != HMC_DATA_TYPE_DER))) {
        hml_error("PEM and DER input type must have PEM or DER output type");
        return HMC_STATUS_FAILURE;
  }
  if (((output_type == HMC_DATA_TYPE_PEM) || (output_type == HMC_DATA_TYPE_DER)) &&
      ((input_type != HMC_DATA_TYPE_PEM) && (input_type != HMC_DATA_TYPE_DER))) {
        hml_error("PEM and DER output type must have PEM or DER input type");
        return HMC_STATUS_FAILURE;
  }
  if (input_type == HMC_DATA_TYPE_BASE64_URLSAFE_NOPADDING) {
    input_type = HMC_DATA_TYPE_BASE64_URLSAFE;
  }
  if ((input_type == output_type) && (hash_type == HMC_HASH_TYPE_NONE)) {
    if (input_len > output_max_len) {
      hml_error("output buffer too small");
      return HMC_STATUS_BUFFER_TOO_SMALL;
    }
    memcpy(output, input, input_len);
    *output_len = input_len;
    return HMC_STATUS_OK;
  }

  size_t decode_output_len;
  size_t decode_output_alloc_len = input_len * 4;
  unsigned char *decode_output = malloc(decode_output_alloc_len);
  const unsigned char *decode_output_ptr = decode_output;
  int len;

  hmc_status status = HMC_STATUS_OK;
  switch (input_type) {
  case HMC_DATA_TYPE_RAW:
    decode_output_len = input_len;
    decode_output_ptr = input;
    break;
  case HMC_DATA_TYPE_BASE64:
    status = hmc_b64_decode(input, input_len, decode_output,
                            decode_output_alloc_len, &decode_output_len);
    break;
  case HMC_DATA_TYPE_BASE64_URLSAFE:
    status = hmc_url_b64_decode(input, input_len, decode_output,
                                decode_output_alloc_len, &decode_output_len);
    break;
  case HMC_DATA_TYPE_PEM:
    switch (input_cred_type) {
      case HMC_CRED_TYPE_NONE:
        hml_error("no cred type specified");
        free(decode_output);
        return HMC_STATUS_FAILURE;
      case HMC_CRED_TYPE_PRIVATE_KEY:
      case HMC_CRED_TYPE_RSA_PRIVATE_KEY:
        len = wc_KeyPemToDer(input, input_len, decode_output,
                          decode_output_alloc_len, NULL);
        break;
      case HMC_CRED_TYPE_PUBLIC_KEY:
      case HMC_CRED_TYPE_RSA_PUBLIC_KEY:
        len = wc_PubKeyPemToDer(input, input_len, decode_output,
                          decode_output_alloc_len);
        break;
      case HMC_CRED_TYPE_CERT:
        len = wc_CertPemToDer(input, input_len, decode_output,
                          decode_output_alloc_len, CERT_TYPE);
        break;
      case HMC_CRED_TYPE_PKCS8:
        len = wc_KeyPemToDer(input, input_len, decode_output,
                          decode_output_alloc_len, NULL);
        break;
      default:
        hml_error("unrecognized cred type");
        free(decode_output);
        return HMC_STATUS_FAILURE;
    }
    if (len <= 0) {
      hml_error("pem to der failed with %d", len);
      status = HMC_STATUS_FAILURE;
    }
    decode_output_len = len;
    if (output_type == HMC_DATA_TYPE_DER) {
      output_type = HMC_DATA_TYPE_RAW;
    }
    break;
  case HMC_DATA_TYPE_DER:
    switch (input_cred_type) {
      case HMC_CRED_TYPE_NONE:
        hml_error("no cred type specified");
        free(decode_output);
        return HMC_STATUS_FAILURE;
      case HMC_CRED_TYPE_PRIVATE_KEY:
        len = wc_DerToPem(input, input_len, decode_output, decode_output_alloc_len,
          ECC_PRIVATEKEY_TYPE);
        break;
      case HMC_CRED_TYPE_RSA_PRIVATE_KEY:
        len = wc_DerToPem(input, input_len, decode_output, decode_output_alloc_len,
          RSA_TYPE);
        break;
      case HMC_CRED_TYPE_RSA_PUBLIC_KEY:
        len = wc_DerToPem(input, input_len, decode_output, decode_output_alloc_len,
          RSA_PUBLICKEY_TYPE);
        break;
      case HMC_CRED_TYPE_PUBLIC_KEY:
        len = wc_DerToPem(input, input_len, decode_output, decode_output_alloc_len,
          ECC_PUBLICKEY_TYPE);
        break;
      case HMC_CRED_TYPE_CERT:
        len = wc_DerToPem(input, input_len, decode_output, decode_output_alloc_len,
          CERT_TYPE);
        break;
      case HMC_CRED_TYPE_PKCS8:
        len = wc_DerToPem(input, input_len, decode_output, decode_output_alloc_len,
          PKCS8_PRIVATEKEY_TYPE);
        break;
      default:
        hml_error("unrecognized cred type");
        free(decode_output);
        return HMC_STATUS_FAILURE;
    }
    if (len <= 0) {
      hml_error("der to pem failed with %d", len);
      status = HMC_STATUS_FAILURE;
    }
    decode_output_len = len;
    if (output_type == HMC_DATA_TYPE_PEM) {
      output_type = HMC_DATA_TYPE_RAW;
    }
    break;
  case HMC_DATA_TYPE_HEX:
    status = hmc_hex_decode(input, input_len, decode_output,
                            decode_output_alloc_len, &decode_output_len);
    break;
  default:
    hml_error("unknown data type");
    status = HMC_STATUS_FAILURE;
    break;
  }

  if (status != HMC_STATUS_OK) {
    hml_error("decode failed");
    free(decode_output);
    return status;
  }

  unsigned char hashed_data[HASH_MAX_SIZE];
  unsigned char double_hashed_data[HASH_MAX_SIZE];
  status = HMC_STATUS_OK;

  switch (hash_type) {
  case HMC_HASH_TYPE_NONE:
    break;
  case HMC_HASH_TYPE_SHA256:
    status = hmc_sha256(decode_output_ptr, decode_output_len, hashed_data);
    if (status != HMC_STATUS_OK) {
      break;
    }
    decode_output_len = SHA256_SIZE;
    decode_output_ptr = hashed_data;
    break;
  case HMC_HASH_TYPE_SHA384:
    status = hmc_sha384(decode_output_ptr, decode_output_len, hashed_data);
    if (status != HMC_STATUS_OK) {
      break;
    }
    decode_output_len = SHA384_SIZE;
    decode_output_ptr = hashed_data;
    break;
  case HMC_HASH_TYPE_SHA1:
    status = hmc_sha1(decode_output_ptr, decode_output_len, hashed_data);
    if (status != HMC_STATUS_OK) {
      break;
    }
    decode_output_len = SHA1_SIZE;
    decode_output_ptr = hashed_data;
    break;
  case HMC_HASH_TYPE_SHA256SHA256:
    status = hmc_sha256(decode_output_ptr, decode_output_len, hashed_data);
    if (status != HMC_STATUS_OK) {
      break;
    }
    status = hmc_sha256(hashed_data, SHA256_SIZE, double_hashed_data);
    if (status != HMC_STATUS_OK) {
      break;
    }
    decode_output_len = SHA256_SIZE;
    decode_output_ptr = double_hashed_data;
    break;
  default:
    status = HMC_STATUS_FAILURE;
    hml_error("unknown hash type");
    break;
  }

  if (status != HMC_STATUS_OK) {
    hml_error("hash failed");
    free(decode_output);
    return status;
  }

  switch (output_type) {
  case HMC_DATA_TYPE_RAW:
    if (decode_output_len > output_max_len) {
      hml_error("output buffer too small %zu > %zu", decode_output_len, output_max_len);
      free(decode_output);
      return HMC_STATUS_BUFFER_TOO_SMALL;
    }
    memcpy(output, decode_output_ptr, decode_output_len);
    *output_len = decode_output_len;
    free(decode_output);
    return HMC_STATUS_OK;
    break;
  case HMC_DATA_TYPE_BASE64:
    status = hmc_b64_encode(decode_output_ptr, decode_output_len, output,
                          output_max_len, output_len);
    free(decode_output);
    return status;
  case HMC_DATA_TYPE_BASE64_URLSAFE:
  case HMC_DATA_TYPE_BASE64_URLSAFE_NOPADDING:
    status = hmc_url_b64_encode(
        decode_output_ptr, decode_output_len, output, output_max_len,
        output_len, output_type == HMC_DATA_TYPE_BASE64_URLSAFE_NOPADDING);
    free(decode_output);
    return status;
  case HMC_DATA_TYPE_HEX:
    status = hmc_hex_encode(decode_output_ptr, decode_output_len, output, output_max_len, output_len);
    free(decode_output);
    return status;
  default:
    hml_error("unknown data type");
    free(decode_output);
    return HMC_STATUS_FAILURE;
  }
  free(decode_output);
  return HMC_STATUS_OK;
}

hmc_status hmc_decrypt_ecc(hmc_data_type key_data_type,
                           const unsigned char *priv_key, size_t priv_key_len,
                           hmc_data_type input_type, const unsigned char *input,
                           size_t input_len, hmc_data_type output_type,
                           unsigned char *output, size_t output_max_len,
                           size_t *output_len) {

  ecc_key priv;
  hmc_status status;
  size_t ciphertext_len = 0;
  int rc;
  WC_RNG rng;
  unsigned char ciphertext[input_len * 4];
  status = hmc_convert(input_type, HMC_CRED_TYPE_NONE, input, input_len, HMC_HASH_TYPE_NONE,
                       HMC_DATA_TYPE_RAW, ciphertext, sizeof(ciphertext),
                       &ciphertext_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  if (key_data_type == HMC_DATA_TYPE_RAW) {
    key_data_type = HMC_DATA_TYPE_DER;
  }
  status =
      hmc_read_private_ecc_key(key_data_type, priv_key, priv_key_len, &priv);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    wc_ecc_free(&priv);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_ecc_set_rng(&priv, &rng);
  if (rc) {
    hml_error("set key rng failed with %d", rc);
    wc_FreeRng(&rng);
    wc_ecc_free(&priv);
    return HMC_STATUS_FAILURE;
  }

  unsigned char decrypted_data[ciphertext_len + 256];
  word32 out_size = sizeof(decrypted_data);
  rc = wc_ecc_decrypt(&priv, NULL, ciphertext, ciphertext_len,
                          decrypted_data, &out_size, NULL);
  wc_FreeRng(&rng);
  wc_ecc_free(&priv);
  if (rc) {
    hml_error("encrypt failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  return hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, decrypted_data, out_size,
                     HMC_HASH_TYPE_NONE, output_type, output, output_max_len,
                     output_len);
}

hmc_status hmc_concat_kdf(const unsigned char *shared_secret, size_t shared_secret_len,
                          const unsigned char *enc, size_t enc_len,
                          const unsigned char *party_u, size_t party_u_len,
                          const unsigned char *party_v, size_t party_v_len,
                          size_t enc_key_numbits,
                          unsigned char *output, size_t output_len) {
  int rc;
  if (output_len != SHA256_SIZE) {
    hml_error("output buffer must be %d bytes", SHA256_SIZE);
    return HMC_STATUS_FAILURE;
  }
  if ((enc_key_numbits != 128) && (enc_key_numbits != 256)) {
    hml_error("enc key must be 128 or 256 bits");
    return HMC_STATUS_FAILURE;
  }
  Sha256 sha256;
  rc = wc_InitSha256(&sha256);
  if (rc) {
    hml_error("init sha256 failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  uint32_t counter = htonl(1);
  rc = wc_Sha256Update(&sha256, (const unsigned char *) &counter, sizeof(counter));
  if (rc) {
    hml_error("sha256 update failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_Sha256Update(&sha256, shared_secret, shared_secret_len);
  if (rc) {
    hml_error("sha256 update failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  uint32_t len = htonl(enc_len);
  rc = wc_Sha256Update(&sha256, (const unsigned char *) &len, sizeof(len));
  if (rc) {
    hml_error("sha256 update failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_Sha256Update(&sha256, enc, enc_len);
  if (rc) {
    hml_error("sha256 update failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  uint32_t apu_len_bytes = htonl(party_u_len), apv_len_bytes = htonl(party_v_len);
  rc = wc_Sha256Update(&sha256, (const unsigned char *) &apu_len_bytes, sizeof(apu_len_bytes));
  if (rc) {
    hml_error("sha256 update failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  if (party_u_len > 0) {
    rc = wc_Sha256Update(&sha256, party_u, party_u_len);
    if (rc) {
      hml_error("sha256 update failed with %d", rc);
      return HMC_STATUS_FAILURE;
    }
  }
  rc = wc_Sha256Update(&sha256, (const unsigned char *) &apv_len_bytes, sizeof(apv_len_bytes));
  if (rc) {
    hml_error("sha256 update failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  if (party_v_len > 0) {
    rc = wc_Sha256Update(&sha256, party_v, party_v_len);
    if (rc) {
      hml_error("sha256 update failed with %d", rc);
      return HMC_STATUS_FAILURE;
    }
  }
  uint32_t enc_key_length = htonl(enc_key_numbits);
  rc = wc_Sha256Update(&sha256, (const unsigned char *) &enc_key_length, sizeof(enc_key_length));
  if (rc) {
    hml_error("sha256 update failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_Sha256Final(&sha256, output);
  if (rc) {
    hml_error("sha256 final failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

hmc_status hmc_encrypt_ecc(hmc_data_type key_data_type,
                           const unsigned char *priv_key, size_t priv_key_len,
                           const unsigned char *pub_key, size_t pub_key_len,
                           const unsigned char *input, size_t input_len,
                           hmc_data_type output_type, unsigned char *output,
                           size_t output_max_len, size_t *output_len) {

  ecc_key pub;
  ecc_key priv;
  hmc_status status;
  unsigned char encrypted_data[input_len + 256];
  WC_RNG rng;
  int rc;

  if (key_data_type == HMC_DATA_TYPE_RAW) {
    key_data_type = HMC_DATA_TYPE_DER;
  }
  status =
      hmc_read_private_ecc_key(key_data_type, priv_key, priv_key_len, &priv);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  status = hmc_read_public_ecc_key(key_data_type, pub_key, pub_key_len, &pub);
  if (status != HMC_STATUS_OK) {
    wc_ecc_free(&priv);
    return status;
  }

  rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    wc_ecc_free(&priv);
    wc_ecc_free(&pub);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_ecc_set_rng(&priv, &rng);
  if (rc) {
    hml_error("set key rng failed with %d", rc);
    wc_FreeRng(&rng);
    wc_ecc_free(&pub);
    wc_ecc_free(&priv);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_ecc_set_rng(&pub, &rng);
  if (rc) {
    hml_error("set key rng failed with %d", rc);
    wc_FreeRng(&rng);
    wc_ecc_free(&pub);
    wc_ecc_free(&priv);
    return HMC_STATUS_FAILURE;
  }

  word32 out_size = sizeof(encrypted_data);
  rc = wc_ecc_encrypt(&priv, &pub, input, input_len, encrypted_data,
                          &out_size, NULL);
  wc_ecc_free(&priv);
  wc_ecc_free(&pub);
  wc_FreeRng(&rng);
  if (rc) {
    hml_error("encrypt failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  return hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, encrypted_data, out_size,
                     HMC_HASH_TYPE_NONE, output_type, output, output_max_len,
                     output_len);
}

// static functions

static hmc_status hmc_decode_aes_key(Aes *aes_key, hmc_data_type key_data_type,
                                     const unsigned char *key, size_t key_len) {
  wc_AesInit(aes_key, NULL, INVALID_DEVID);

  size_t key_output_len = 0;
  unsigned char key_output[KEY_DECODE_BUF_SIZE];
  hmc_status status = hmc_convert(
      key_data_type, HMC_CRED_TYPE_NONE, key, key_len, HMC_HASH_TYPE_NONE, HMC_DATA_TYPE_RAW,
      key_output, sizeof(key_output), &key_output_len);
  if (status != HMC_STATUS_OK) {
    wc_AesFree(aes_key);
    return status;
  }
  if ((key_output_len != AES_KEY_SIZE) &&
      (key_output_len != AES_KEY_SIZE_128)) {
    wc_AesFree(aes_key);
    return HMC_STATUS_INVALID_KEY_SIZE;
  }

  int rc = wc_AesGcmSetKey(aes_key, key_output, key_output_len);
  if (rc) {
    hml_error("set key failed with %d", rc);
    wc_AesFree(aes_key);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

static hmc_status hmc_generate_ecc_key_pair(
    hmc_key_type key_type, hmc_data_type output_type,
    unsigned char *private_key_output, size_t private_key_output_max_len,
    size_t *private_key_output_len, unsigned char *public_key_output,
    size_t public_key_output_max_len, size_t *public_key_output_len) {

  ecc_key key;
  int keysize;
  int curve_id;
  hmc_status status;
  WC_RNG rng;

  if (key_type == HMC_KEY_TYPE_ECC256) {
    keysize = 32;
    curve_id = ECC_SECP256R1;
  } else if (key_type == HMC_KEY_TYPE_ECC384) {
    keysize = 48;
    curve_id = ECC_SECP384R1;
  } else if (key_type == HMC_KEY_TYPE_ECC521) {
    keysize = 66;
    curve_id = ECC_SECP521R1;
  } else {
    hml_error("unknown key type %d", key_type);
    return HMC_STATUS_FAILURE;
  }

  int rc = wc_ecc_init(&key);
  if (rc) {
    hml_error("key init failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    wc_ecc_free(&key);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_ecc_make_key_ex(&rng, keysize, &key, curve_id);
  if (rc) {
    hml_error("make key failed with %d", rc);
    wc_FreeRng(&rng);
    wc_ecc_free(&key);
    return HMC_STATUS_FAILURE;
  }
  unsigned char der[MAX_DER_SIZE];
  rc = wc_EccPublicKeyToDer(&key, der, sizeof(der), 1);
  if (rc <= 0) {
    hml_error("key to der failed with %d", rc);
    wc_FreeRng(&rng);
    wc_ecc_free(&key);
    return HMC_STATUS_FAILURE;
  }

  if (output_type == HMC_DATA_TYPE_RAW) {
    output_type = HMC_DATA_TYPE_DER;
  }
  status = hmc_convert(HMC_DATA_TYPE_DER, HMC_CRED_TYPE_PUBLIC_KEY, der, rc, HMC_HASH_TYPE_NONE,
                       output_type, public_key_output,
                       public_key_output_max_len, public_key_output_len);
  if (status != HMC_STATUS_OK) {
    wc_FreeRng(&rng);
    wc_ecc_free(&key);
    return status;
  }

  rc = wc_EccKeyToDer(&key, der, sizeof(der));
  if (rc <= 0) {
    hml_error("key to der failed with %d", rc);
    wc_FreeRng(&rng);
    wc_ecc_free(&key);
    return HMC_STATUS_FAILURE;
  }

  wc_FreeRng(&rng);
  wc_ecc_free(&key);

  return hmc_convert(HMC_DATA_TYPE_DER, HMC_CRED_TYPE_PRIVATE_KEY, der, rc, HMC_HASH_TYPE_NONE,
                     output_type, private_key_output,
                     private_key_output_max_len, private_key_output_len);
}

static hmc_status hmc_generate_rsa_key_pair(
    hmc_key_type key_type, hmc_data_type output_type,
    unsigned char *private_key_output, size_t private_key_output_max_len,
    size_t *private_key_output_len, unsigned char *public_key_output,
    size_t public_key_output_max_len, size_t *public_key_output_len) {

  int keysize_bits;
  long public_exponent;
  hmc_status status;
  WC_RNG rng;
  RsaKey key;

  if (key_type == HMC_KEY_TYPE_RSA3072_E3) {
    keysize_bits = 3072;
    public_exponent = 3;
  } else {
    hml_error("unknown key type %d", key_type);
    return HMC_STATUS_FAILURE;
  }

  int rc = wc_InitRsaKey(&key, NULL);
  if (rc) {
    hml_error("rsa key init failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    wc_FreeRsaKey(&key);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_MakeRsaKey(&key, keysize_bits, public_exponent, &rng);
  if (rc) {
    hml_error("rsa make key failed with %d", rc);
    wc_FreeRng(&rng);
    wc_FreeRsaKey(&key);
    return HMC_STATUS_FAILURE;
  }
  unsigned char der[MAX_RSA_DER_SIZE];
  rc = wc_RsaKeyToPublicDer(&key, der, sizeof(der));
  if (rc <= 0) {
    hml_error("rsa public key to der failed with %d", rc);
    wc_FreeRng(&rng);
    wc_FreeRsaKey(&key);
    return HMC_STATUS_FAILURE;
  }

  if (output_type == HMC_DATA_TYPE_RAW) {
    output_type = HMC_DATA_TYPE_DER;
  }
  status = hmc_convert(HMC_DATA_TYPE_DER, HMC_CRED_TYPE_RSA_PUBLIC_KEY, der, rc, HMC_HASH_TYPE_NONE,
                       output_type, public_key_output,
                       public_key_output_max_len, public_key_output_len);
  if (status != HMC_STATUS_OK) {
    wc_FreeRng(&rng);
    wc_FreeRsaKey(&key);
    return status;
  }

  rc = wc_RsaKeyToDer(&key, der, sizeof(der));
  if (rc <= 0) {
    hml_error("rsa private key to der failed with %d", rc);
    wc_FreeRng(&rng);
    wc_FreeRsaKey(&key);
    return HMC_STATUS_FAILURE;
  }

  wc_FreeRng(&rng);
  wc_FreeRsaKey(&key);

  return hmc_convert(HMC_DATA_TYPE_DER, HMC_CRED_TYPE_RSA_PRIVATE_KEY, der, rc, HMC_HASH_TYPE_NONE,
                     output_type, private_key_output,
                     private_key_output_max_len, private_key_output_len);
}

static hmc_status hmc_read_public_ecc_key(hmc_data_type key_data_type,
                                          const unsigned char *input,
                                          size_t input_len, ecc_key *key) {
  unsigned char der_buf[MAX_DER_SIZE];
  hmc_status status;
  int rc;

  size_t der_buf_len;
  status =
      hmc_convert(key_data_type, HMC_CRED_TYPE_PUBLIC_KEY, input, input_len, HMC_HASH_TYPE_NONE,
                  HMC_DATA_TYPE_DER, der_buf, sizeof(der_buf), &der_buf_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  word32 idx = 0;
  rc = wc_ecc_init(key);
  if (rc) {
    hml_error("key init failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_EccPublicKeyDecode(der_buf, &idx, key, der_buf_len);
  if (rc) {
    hml_error("key decode failed with %d", rc);
    wc_ecc_free(key);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

static hmc_status hmc_read_private_ecc_key(hmc_data_type key_data_type,
                                           const unsigned char *input,
                                           size_t input_len, ecc_key *key) {
  unsigned char der_buf[MAX_DER_SIZE];
  hmc_status status;

  size_t der_buf_len;
  status =
      hmc_convert(key_data_type, HMC_CRED_TYPE_PRIVATE_KEY, input, input_len, HMC_HASH_TYPE_NONE,
                  HMC_DATA_TYPE_DER, der_buf, sizeof(der_buf), &der_buf_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  word32 idx = 0;
  int rc = wc_ecc_init(key);
  if (rc) {
    hml_error("key init failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_EccPrivateKeyDecode(der_buf, &idx, key, der_buf_len);
  if (rc) {
    hml_error("key decode failed with %d", rc);
    wc_ecc_free(key);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

static hmc_status hmc_read_public_rsa_key(hmc_data_type key_data_type,
                                           const unsigned char *input,
                                           size_t input_len, RsaKey *key) {
  unsigned char der_buf[MAX_RSA_DER_SIZE];
  hmc_status status;

  size_t der_buf_len;
  status =
      hmc_convert(key_data_type, HMC_CRED_TYPE_RSA_PUBLIC_KEY, input, input_len, HMC_HASH_TYPE_NONE,
                  HMC_DATA_TYPE_DER, der_buf, sizeof(der_buf), &der_buf_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  word32 idx = 0;
  int rc = wc_InitRsaKey(key, NULL);
  if (rc) {
    hml_error("key init failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  rc = wc_RsaPublicKeyDecode(der_buf, &idx, key, der_buf_len);
  if (rc) {
    hml_error("key decode failed with %d", rc);
    wc_FreeRsaKey(key);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

static hmc_status hmc_read_private_rsa_key(hmc_data_type key_data_type, hmc_cred_type cred_type,
                                           const unsigned char *input,
                                           size_t input_len, RsaKey *key) {
  unsigned char der_buf[MAX_RSA_DER_SIZE];
  hmc_status status;

  size_t der_buf_len;
  status =
      hmc_convert(key_data_type, cred_type, input, input_len, HMC_HASH_TYPE_NONE,
                  HMC_DATA_TYPE_DER, der_buf, sizeof(der_buf), &der_buf_len);
  if (status != HMC_STATUS_OK) {
    return status;
  }

  word32 idx = 0;
  int rc = wc_InitRsaKey(key, NULL);
  if (rc) {
    hml_error("key init failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  if (cred_type == HMC_CRED_TYPE_PKCS8) {
     rc = wc_GetPkcs8TraditionalOffset(der_buf, &idx, der_buf_len);
     if (rc < 0) {
       hml_error("get offset failed with %d", rc);
       wc_FreeRsaKey(key);
       return HMC_STATUS_FAILURE;
     }
  }

  rc = wc_RsaPrivateKeyDecode(der_buf, &idx, key, der_buf_len);
  if (rc) {
    hml_error("key decode failed with %d", rc);
    wc_FreeRsaKey(key);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

static hmc_status hmc_sha256(const unsigned char *data, size_t data_len,
                             unsigned char *output) {
  int rc = wc_Sha256Hash(data, data_len, output);
  if (rc) {
    hml_error("sha256 failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

static hmc_status hmc_sha384(const unsigned char *data, size_t data_len,
                             unsigned char *output) {
  int rc = wc_Sha384Hash(data, data_len, output);
  if (rc) {
    hml_error("sha384 failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

static hmc_status hmc_sha512(const unsigned char *data, size_t data_len,
                             unsigned char *output) {
  int rc = wc_Sha512Hash(data, data_len, output);
  if (rc) {
    hml_error("sha512 failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

static hmc_status hmc_sha1(const unsigned char *data, size_t data_len,
                           unsigned char *output) {
  int rc = wc_ShaHash(data, data_len, output);
  if (rc) {
    hml_error("sha384 failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  return HMC_STATUS_OK;
}

static hmc_status hmc_create_ecc_signature(
    hmc_key_type key_type, hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *input, size_t input_len, hmc_data_type output_type,
    unsigned char *output, size_t output_max_len, size_t *output_len) {
  unsigned char msg_hash[HASH_MAX_SIZE];
  size_t msg_hash_len, key_len;
  ecc_key priv;
  hmc_status status;
  WC_RNG rng;

  switch (key_type) {
  case HMC_KEY_TYPE_ECC256:
	  msg_hash_len = SHA256_SIZE;
	  key_len = 32;
	  break;
  case HMC_KEY_TYPE_ECC384:
	  msg_hash_len = SHA384_SIZE;
	  key_len = 48;
	  break;
  case HMC_KEY_TYPE_ECC521:
	  msg_hash_len = SHA512_SIZE;
	  key_len = 66;
	  break;
  default:
    hml_error("key type %d not supported", key_type);
    return HMC_STATUS_FAILURE; 
  }

  if (key_data_type == HMC_DATA_TYPE_RAW) {
    key_data_type = HMC_DATA_TYPE_DER;
  }

  status = hmc_read_private_ecc_key(key_data_type, private_key, private_key_len, &priv);
  if (status != HMC_STATUS_OK) {
    return status;
  }
  if (wc_ecc_size(&priv) != key_len) {
    hml_error("key size does not match parameters, %d != %zu", wc_ecc_size(&priv), key_len);
    wc_ecc_free(&priv);
    return HMC_STATUS_INVALID_KEY_SIZE;
  }

  switch (key_type) {
  case HMC_KEY_TYPE_ECC256: status = hmc_sha256(input, input_len, msg_hash); break;
  case HMC_KEY_TYPE_ECC384: status = hmc_sha384(input, input_len, msg_hash); break;
  case HMC_KEY_TYPE_ECC521: status = hmc_sha512(input, input_len, msg_hash); break;
  default: abort(); // unreachable
  }
  if (status != HMC_STATUS_OK) {
    wc_ecc_free(&priv);
    return status;
  }

  int rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    wc_ecc_free(&priv);
    return HMC_STATUS_FAILURE;
  }

  // We only create signatures that match HMC_SIG_FORMAT_FIXED...

  mp_int r, s;
  mp_init(&r);
  mp_init(&s);

  rc = wc_ecc_sign_hash_ex(msg_hash, msg_hash_len, &rng, &priv, &r, &s);
  wc_ecc_free(&priv);
  wc_FreeRng(&rng);
  if (rc) {
    mp_free(&r);
    mp_free(&s);
    hml_error("sign failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  const size_t sig_len = 2 * key_len;
  unsigned char sig_buf[sig_len];
  word32 r_len = key_len;
  word32 s_len = key_len;

  rc = wc_export_int(&r, sig_buf, &r_len, key_len, WC_TYPE_UNSIGNED_BIN);
  if (!rc) {
    rc = wc_export_int(&s, sig_buf+key_len, &s_len, key_len, WC_TYPE_UNSIGNED_BIN);
  }
  mp_free(&r);
  mp_free(&s);
  if (rc) {
    hml_error("wc_export_int failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  return hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, sig_buf, sig_len,
                     HMC_HASH_TYPE_NONE, output_type, output, output_max_len,
                     output_len);
}

static hmc_status
hmc_verify_ecc_signature(hmc_key_type key_type, hmc_data_type key_data_type,
                         const unsigned char *public_key, size_t public_key_len,
                         const unsigned char *input, size_t input_len,
                         hmc_sig_format signature_format,
                         hmc_data_type signature_data_type,
                         const unsigned char *signature, size_t signature_len,
                         bool *verified) {
  unsigned char sig_buf[SIGN_BUF_SIZE];
  size_t sig_len = 0;
  unsigned char msg_hash[HASH_MAX_SIZE];
  size_t msg_hash_len, key_len;
  ecc_key pub;
  hmc_status status;

  switch (key_type) {
  case HMC_KEY_TYPE_ECC256:
	  msg_hash_len = SHA256_SIZE;
	  key_len = 32;
	  break;
  case HMC_KEY_TYPE_ECC384:
	  msg_hash_len = SHA384_SIZE;
	  key_len = 48;
	  break;
  case HMC_KEY_TYPE_ECC521:
	  msg_hash_len = SHA512_SIZE;
	  key_len = 66;
	  break;
  default:
    hml_error("key type %d not supported", key_type);
    return HMC_STATUS_FAILURE; 
  }

  if (key_data_type == HMC_DATA_TYPE_RAW) {
    key_data_type = HMC_DATA_TYPE_DER;
  }
  status = hmc_read_public_ecc_key(key_data_type, public_key, public_key_len, &pub);
  if (status != HMC_STATUS_OK) {
    return status;
  }
  if (wc_ecc_size(&pub) != key_len) {
    hml_error("key size does not match parameters, %d != %zu", wc_ecc_size(&pub), key_len);
    wc_ecc_free(&pub);
    return HMC_STATUS_INVALID_KEY_SIZE;
  }

  switch (key_type) {
  case HMC_KEY_TYPE_ECC256: status = hmc_sha256(input, input_len, msg_hash); break;
  case HMC_KEY_TYPE_ECC384: status = hmc_sha384(input, input_len, msg_hash); break;
  case HMC_KEY_TYPE_ECC521: status = hmc_sha512(input, input_len, msg_hash); break;
  default: abort(); // unreachable
  }
  if (status != HMC_STATUS_OK) {
    wc_ecc_free(&pub);
    return status;
  }

  status = hmc_convert(signature_data_type, HMC_CRED_TYPE_NONE, signature, signature_len,
                       HMC_HASH_TYPE_NONE, HMC_DATA_TYPE_RAW, sig_buf,
                       sizeof(sig_buf), &sig_len);
  if (status != HMC_STATUS_OK) {
    wc_ecc_free(&pub);
    return status;
  }

  int rc;
  int verified_status = 0;
  if (signature_format == HMC_SIG_FORMAT_FIXED) {
    if (sig_len != 2 * key_len) {
      hml_error("decoded fixed signature is not the right size, %zu != %zu", sig_len, 2 * key_len);
      wc_ecc_free(&pub);
      return HMC_STATUS_FAILURE;
    }
    // The signature is r & s, concatenated together, each the same length as the key & hash.
    mp_int r, s;
    mp_init(&r);
    mp_init(&s);
    rc = mp_read_unsigned_bin(&r, sig_buf, key_len);
    if (!rc) {
      rc = mp_read_unsigned_bin(&s, sig_buf+key_len, key_len);
    }
    if (rc) {
      hml_error("failed to read signature into mp_ints: %d", rc);
      wc_ecc_free(&pub);
      mp_free(&r);
      mp_free(&s);
      return HMC_STATUS_FAILURE;
    }
    rc = wc_ecc_verify_hash_ex(&r, &s, msg_hash, msg_hash_len, &verified_status, &pub);
    mp_free(&r);
    mp_free(&s);
  } else if (signature_format == HMC_SIG_FORMAT_ASN1DER) {
    rc = wc_ecc_verify_hash(sig_buf, sig_len, msg_hash, msg_hash_len, &verified_status, &pub);
  } else {
    hml_error("invalid signature_format %d", signature_format);
    wc_ecc_free(&pub);
    return HMC_STATUS_FAILURE;
  }
  wc_ecc_free(&pub);
  if (rc) {
    hml_error("verify failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  *verified = (verified_status == 1);
  return HMC_STATUS_OK;
}

static hmc_status hmc_create_self_signed_ecc_certificate(
    const char *common_name, size_t common_name_len,
    int is_CA, int days_valid, unsigned char path_length,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type, hmc_data_type output_data_type,
    unsigned char *output, size_t output_max_len, size_t *output_len
) {
  if (common_name_len == 0) {
    hml_error("common name is empty");
    return HMC_STATUS_FAILURE;
  } else if (common_name_len >= CTC_NAME_SIZE) {
    hml_error("common name too long");
    return HMC_STATUS_FAILURE;
  }
  if (is_CA != 0 && is_CA != 1) {
    hml_error("invalid is_CA");
    return HMC_STATUS_FAILURE;
  }
  if ((days_valid < 1) || (days_valid > 365)) {
    hml_error("invalid days valid");
    return HMC_STATUS_FAILURE;
  }
  if (is_CA == 0 && path_length != 0) {
    hml_error("path length must be 0 for non-CA");
    return HMC_STATUS_FAILURE;
  }
  if (path_length != 0 && path_length != 1) {
    hml_error("invalid path length");
    return HMC_STATUS_FAILURE;
  }
  if (!((output_sig_type == HMC_SIG_TYPE_CTC_SHA256wECDSA) ||
       (output_sig_type == HMC_SIG_TYPE_CTC_SHA384wECDSA) ||
       (output_sig_type == HMC_SIG_TYPE_CTC_SHA512wECDSA))) {
    hml_error("signature type %d not supported", output_sig_type);
    return HMC_STATUS_FAILURE;
  }
  if (output_data_type == HMC_DATA_TYPE_RAW) {
    output_data_type = HMC_DATA_TYPE_DER;
  }
  if ((output_data_type != HMC_DATA_TYPE_PEM) &&
      (output_data_type != HMC_DATA_TYPE_DER)) {
    hml_error("output cert data type not supported");
    return HMC_STATUS_FAILURE;
  }
  return hmc_create_self_signed_ecc_certificate_internal(
      common_name, common_name_len,
      is_CA, days_valid, path_length,
      key_data_type,
      private_key, private_key_len,
      public_key, public_key_len,
      output_sig_type, output_data_type,
      output, output_max_len, output_len);
}

static hmc_status hmc_create_self_signed_ecc_certificate_internal(
    const char *common_name, size_t common_name_len,
    int is_CA, int days_valid, unsigned char path_length,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type, hmc_data_type output_data_type,
    unsigned char *output, size_t output_max_len, size_t *output_len) {
  int rc;
  int init_rng = 0, init_priv = 0, init_pub = 0;
  hmc_status status = HMC_STATUS_OK;

  unsigned char cert_der_buf[MAX_CERT_SIZE];

  Cert cert;
  ecc_key priv, pub;
  WC_RNG rng;

  rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }
  init_rng = 1;

  rc = wc_InitCert(&cert);
  if (rc) {
    hml_error("cert init failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  strncpy(cert.subject.commonName, common_name,
          common_name_len);
  if (common_name_len < sizeof(cert.subject.commonName)) {
    cert.subject.commonName[common_name_len] = '\0';
  }

  cert.isCA = is_CA;
  cert.pathLen = path_length;
  cert.daysValid = days_valid;
  cert.sigType = 0;

  switch (output_sig_type) {
  case HMC_SIG_TYPE_CTC_SHA256wECDSA:
    cert.sigType = CTC_SHA256wECDSA;
    break;
  case HMC_SIG_TYPE_CTC_SHA384wECDSA:
    cert.sigType = CTC_SHA384wECDSA;
    break;
  case HMC_SIG_TYPE_CTC_SHA512wECDSA:
    cert.sigType = CTC_SHA512wECDSA;
    break;
  case HMC_SIG_TYPE_NONE:
  default:
    hml_error("invalid output signature type: %d", output_sig_type);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  status = hmc_read_private_ecc_key(key_data_type, private_key, private_key_len,
                                    &priv);
  if (status != HMC_STATUS_OK) {
    hml_error("read private key failed with %d", status);
    goto exit;
  }
  init_priv = 1;

  status = hmc_read_public_ecc_key(key_data_type, public_key, public_key_len,
                                    &pub);
  if (status != HMC_STATUS_OK) {
    hml_error("read public key failed with %d", status);
    goto exit;
  }
  init_pub = 1;

  rc = wc_SetSubjectKeyIdFromPublicKey(&cert, NULL, &pub);
  if (rc) {
    hml_error("set subject key id failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  rc = wc_SetAuthKeyIdFromPublicKey(&cert, NULL, &pub);
  if (rc) {
    hml_error("set auth key id failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  rc = wc_MakeCert(&cert, cert_der_buf, MAX_CERT_SIZE, NULL, &priv, &rng);
  if (rc <= 0) {
    hml_error("make certificate failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  rc = wc_SignCert(cert.bodySz, cert.sigType,
    cert_der_buf, MAX_CERT_SIZE, NULL, &priv, &rng);
  if (rc <= 0) {
    hml_error("sign certificate failed with %d for sigtype %d", rc,
      cert.sigType);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  if (output_data_type == HMC_DATA_TYPE_PEM) {
    rc = wc_DerToPem(cert_der_buf, rc, output, output_max_len, CERT_TYPE);
    if (rc <= 0) {
      hml_error("certificate der to pem failed with %d", rc);
      status =
          (rc == BUFFER_E) ? HMC_STATUS_BUFFER_TOO_SMALL : HMC_STATUS_FAILURE;
      goto exit;
    }
    *output_len = rc;
  } else {
    if (rc > output_max_len) {
      status = HMC_STATUS_BUFFER_TOO_SMALL;
      goto exit;
    }
    *output_len = rc;
    memcpy(output, cert_der_buf, rc);
  }

  if (status != HMC_STATUS_OK) {
    hml_error("create self-signed certificate reported status %d on success", status);
  }

exit:
  if (init_priv) {
    wc_ecc_free(&priv);
  }
  if (init_pub) {
    wc_ecc_free(&pub);
  }
  if (init_rng) {
    wc_FreeRng(&rng);
  }

  return status;

}

static hmc_status hmc_create_ecc_certificate_internal(
    const unsigned char *csr, size_t csr_len, hmc_data_type csr_data_type,
    int is_intermediate_CA, int days_valid, unsigned char path_length,
    const unsigned char *ca_cert, size_t ca_cert_len,
    hmc_data_type ca_cert_data_type,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type,
    hmc_data_type output_data_type, unsigned char *output,
    size_t output_max_len, size_t *output_len) {

  size_t csr_der_len;
  unsigned char csr_der_buf[MAX_CERT_SIZE];
  const unsigned char *csr_der_ptr;

  word32 csr_pubkey_len;
  unsigned char csr_pubkey_buf[MAX_CERT_SIZE];

  size_t cert_der_len;
  unsigned char cert_der_buf[MAX_CERT_SIZE];
  const unsigned char *cert_der_ptr;

  struct DecodedCert decoded_csr;
  Cert cert;
  ecc_key priv, pub;
  ecc_key cert_key;
  WC_RNG rng;

  int rc;
  int init_rng = 0, init_priv = 0, init_pub = 0;
  int init_cert_key = 0, init_decoded_csr = 0;
  hmc_status status = HMC_STATUS_OK;

  rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }
  init_rng = 1;

  if (csr_data_type == HMC_DATA_TYPE_PEM) {
    // There is issue on osx/mac where wc_ParseCert fails if we don't zero this buffer
    memset(csr_der_buf, 0, sizeof(csr_der_buf));
    rc = wc_CertPemToDer(csr, csr_len, csr_der_buf, sizeof(csr_der_buf),
                          CERTREQ_TYPE);
    if (rc <= 0) {
      hml_error("certificate signing request (csr) pem to der failed with %d",
                rc);
      status = HMC_STATUS_FAILURE;
      goto exit;
    }
    csr_der_len = rc;
    csr_der_ptr = csr_der_buf;
  } else {
    csr_der_len = csr_len;
    csr_der_ptr = csr;
  }

  if (ca_cert_data_type == HMC_DATA_TYPE_PEM) {
    rc = wc_CertPemToDer(ca_cert, ca_cert_len, cert_der_buf,
                          sizeof(cert_der_buf), CERT_TYPE);
    if (rc <= 0) {
      hml_error("certificate pem to der failed with %d", rc);
      status = HMC_STATUS_FAILURE;
      goto exit;
    }
    cert_der_len = rc;
    cert_der_ptr = cert_der_buf;
  } else {
    cert_der_len = ca_cert_len;
    cert_der_ptr = ca_cert;
  }

  rc = wc_InitCert(&cert);
  if (rc) {
    hml_error("cert init failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  wc_InitDecodedCert(&decoded_csr, csr_der_ptr, csr_der_len, NULL);
  init_decoded_csr = 1;

  rc = wc_ParseCert(&decoded_csr, CERTREQ_TYPE, NO_VERIFY, NULL);
  if (rc) {
    hml_error("csr parse failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  strncpy(cert.subject.commonName, decoded_csr.subjectCN,
          decoded_csr.subjectCNLen);
  if (decoded_csr.subjectCNLen < sizeof(cert.subject.commonName)) {
    cert.subject.commonName[decoded_csr.subjectCNLen] = '\0';
  }

  cert.isCA = is_intermediate_CA;
  cert.pathLen = path_length;
  cert.daysValid = days_valid;
  cert.sigType = 0;

  switch (output_sig_type) {
  case HMC_SIG_TYPE_CTC_SHA256wECDSA:
    cert.sigType = CTC_SHA256wECDSA;
    break;
  case HMC_SIG_TYPE_CTC_SHA384wECDSA:
    cert.sigType = CTC_SHA384wECDSA;
    break;
  case HMC_SIG_TYPE_CTC_SHA512wECDSA:
    cert.sigType = CTC_SHA512wECDSA;
    break;
  case HMC_SIG_TYPE_NONE:
  default:
    hml_error("invalid output signature type: %d", output_sig_type);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  status = hmc_read_private_ecc_key(key_data_type, private_key, private_key_len,
                                    &priv);
  if (status != HMC_STATUS_OK) {
    hml_error("read private key failed with %d", status);
    goto exit;
  }
  init_priv = 1;

  status = hmc_read_public_ecc_key(key_data_type, public_key, public_key_len,
                                    &pub);
  if (status != HMC_STATUS_OK) {
    hml_error("read public key failed with %d", status);
    goto exit;
  }
  init_pub = 1;

  csr_pubkey_len = sizeof(csr_pubkey_buf);
  status =
      wc_GetPubKeyDerFromCert(&decoded_csr, csr_pubkey_buf, &csr_pubkey_len);
  if (status != HMC_STATUS_OK) {
    goto exit;
  }

  status = hmc_read_public_ecc_key(HMC_DATA_TYPE_DER, csr_pubkey_buf,
                                   csr_pubkey_len, &cert_key);
  if (status != HMC_STATUS_OK) {
    hml_error("read cert_key public key failed with %d", status);
    goto exit;
  }
  init_cert_key = 1;

  rc = wc_SetSubjectKeyIdFromPublicKey(&cert, NULL, &cert_key);
  if (rc) {
    hml_error("set subject key id failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  rc = wc_SetAuthKeyIdFromPublicKey(&cert, NULL, &pub);
  if (rc) {
    hml_error("set auth key id failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  if (is_intermediate_CA) {
    rc = wc_SetKeyUsage(&cert, "keyCertSign,cRLSign");
    if (rc) {
      hml_error("set key usage failed with %d", rc);
      status = HMC_STATUS_FAILURE;
      goto exit;
    }
  }

  // read from cert_der_ptr (either ca_cert or cert_der_buf)
  rc = wc_SetIssuerBuffer(&cert, cert_der_ptr, cert_der_len);
  if (rc) {
    hml_error("set issuer buffer failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  // write to cert_der_buf
  // On successfully making an x509 certificate from the
  // specified input cert, returns the size of the cert generated.
  rc = wc_MakeCert(&cert, cert_der_buf, MAX_CERT_SIZE, NULL, &cert_key, &rng);
  if (rc <= 0) {
    hml_error("make certificate failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  // write to cert_der_buf
  // On successfully signing the certificate, returns the new
  // size of the cert (including signature).
  rc = wc_SignCert(cert.bodySz, cert.sigType, cert_der_buf, MAX_CERT_SIZE, NULL,
                   &priv, &rng);
  if (rc <= 0) {
    hml_error("sign certificate failed with %d for sigtype %d", rc,
              cert.sigType);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  if (output_data_type == HMC_DATA_TYPE_PEM) {
    rc = wc_DerToPem(cert_der_buf, rc, output, output_max_len, CERT_TYPE);
    if (rc <= 0) {
      hml_error("certificate der to pem failed with %d", rc);
      status =
          (rc == BUFFER_E) ? HMC_STATUS_BUFFER_TOO_SMALL : HMC_STATUS_FAILURE;
      goto exit;
    }
    *output_len = rc;
  } else {
    if (rc > output_max_len) {
      status = HMC_STATUS_BUFFER_TOO_SMALL;
      goto exit;
    }
    *output_len = rc;
    memcpy(output, cert_der_buf, rc);
  }

  if (status != HMC_STATUS_OK) {
    hml_error("create certificate reported status %d on success", status);
  }

exit:
  if (init_priv) {
    wc_ecc_free(&priv);
  }
  if (init_pub) {
    wc_ecc_free(&pub);
  }
  if (init_cert_key) {
    wc_ecc_free(&cert_key);
  }
  if (init_decoded_csr) {
    wc_FreeDecodedCert(&decoded_csr);
  }
  if (init_rng) {
    wc_FreeRng(&rng);
  }

  return status;
}

static hmc_status hmc_create_ecc_certificate_signing_request(
  const char *common_name, size_t common_name_len,
  hmc_key_type key_type, hmc_data_type key_data_type,
  const unsigned char *private_key, size_t private_key_len,
  hmc_sig_type output_sig_type,
  hmc_data_type output_data_type, unsigned char *output,
  size_t output_max_len, size_t *output_len) {

  ecc_key priv;
  WC_RNG rng;

  size_t csr_der_len;
  unsigned char csr_der_buf[MAX_CERT_SIZE];

  int rc;
  int init_rng = 0, init_priv = 0;

  hmc_status status = HMC_STATUS_OK;
  Cert csr;

  rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }
  init_rng = 1;

  rc = wc_InitCert(&csr);
  if (rc) {
    hml_error("csr init failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  strncpy(csr.subject.commonName, common_name, common_name_len);
  if (common_name_len < sizeof(csr.subject.commonName)) {
    csr.subject.commonName[common_name_len] = '\0';
  }
  csr.version = 0;

  status = hmc_read_private_ecc_key(key_data_type, private_key, private_key_len,
                                    &priv);
  if (status != HMC_STATUS_OK) {
    hml_error("csr read private key failed with %d", status);
    goto exit;
  }
  init_priv = 1;

  rc = wc_MakeCertReq_ex(&csr, csr_der_buf, sizeof(csr_der_buf), ECC_TYPE, &priv);
  if (rc <= 0) {
    hml_error("csr make certificate request failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }
  csr_der_len = rc;

  switch (output_sig_type) {
  case HMC_SIG_TYPE_CTC_SHA256wECDSA:
    csr.sigType = CTC_SHA256wECDSA;
    break;
  case HMC_SIG_TYPE_CTC_SHA384wECDSA:
    csr.sigType = CTC_SHA384wECDSA;
    break;
  case HMC_SIG_TYPE_CTC_SHA512wECDSA:
    csr.sigType = CTC_SHA512wECDSA;
    break;
  case HMC_SIG_TYPE_NONE:
  default:
    hml_error("csr invalid output signature type: %d", output_sig_type);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }

  rc = wc_SignCert_ex(csr.bodySz, csr.sigType, csr_der_buf, sizeof(csr_der_buf),
    ECC_TYPE, &priv, &rng);
  if (rc <= 0) {
    hml_error("csr sign certificate request failed with %d", rc);
    status = HMC_STATUS_FAILURE;
    goto exit;
  }
  csr_der_len = rc;

  if (output_data_type == HMC_DATA_TYPE_PEM) {
    rc = wc_DerToPem(csr_der_buf, csr_der_len, output, output_max_len, CERTREQ_TYPE);
    if (rc <= 0) {
      hml_error("csr der to pem failed with %d", rc);
      status =
          (rc == BUFFER_E) ? HMC_STATUS_BUFFER_TOO_SMALL : HMC_STATUS_FAILURE;
      goto exit;
    }
    *output_len = rc;
  } else {
    if (csr_der_len > output_max_len) {
      status = HMC_STATUS_BUFFER_TOO_SMALL;
      goto exit;
    }
    *output_len = csr_der_len;
    memcpy(output, csr_der_buf, csr_der_len);
  }

  if (status != HMC_STATUS_OK) {
    hml_error("create certificate signing request reported status %d on success", status);
  }

exit:
  if (init_priv) {
    wc_ecc_free(&priv);
  }
  if (init_rng) {
    wc_FreeRng(&rng);
  }

  return status;
}

static hmc_status hmc_url_b64_encode(const unsigned char *data, size_t data_len,
                                     unsigned char *output,
                                     size_t output_max_len, size_t *output_len,
                                     bool nopadding) {
  word32 len = output_max_len - 1; // wolfcrypt will add a null byte after the decoded data

  int rc = Base64_Encode_NoNl(data, data_len, (unsigned char *)output, &len);
  if (rc) {
    hml_error("b64 encode failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  output[len] = '\0';
  *output_len = len;
  for (int i = 0; i < len; i++) {
    if (output[i] == '+') {
      output[i] = '-';
    } else if (output[i] == '/') {
      output[i] = '_';
    } else if (nopadding && (output[i] == '=')) {
      output[i] = '\0';
      if (i < *output_len) {
        *output_len = i;
      }
    }
  }
  return HMC_STATUS_OK;
}

static hmc_status hmc_url_b64_decode(const unsigned char *data, size_t data_len,
                                     unsigned char *output,
                                     size_t output_max_len,
                                     size_t *output_len) {
  word32 len = output_max_len - 1; // wolfcrypt will add a null byte after the decoded data
  unsigned char data_copy[data_len + 4];
  memcpy(data_copy, data, data_len);

  size_t padding_needed =  4 - (data_len % 4);
  if (padding_needed && (padding_needed < 4)) {
     for (size_t i=0; i<padding_needed; i++) {
       data_copy[data_len++] = '=';
     }
  }
  data_copy[data_len] = '\0';

  for (int i = 0; i < data_len; i++) {
    if (data_copy[i] == '-') {
      data_copy[i] = '+';
    } else if (data_copy[i] == '_') {
      data_copy[i] = '/';
    }
  }
  int rc = Base64_Decode((unsigned char *)data_copy, data_len, output, &len);
  if (rc < 0) {
    hml_error("b64 decode failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  *output_len = len;
  output[len] = '\0';

  return HMC_STATUS_OK;
}

static hmc_status hmc_b64_encode(const unsigned char *data, size_t data_len,
                                 unsigned char *output, size_t output_max_len,
                                 size_t *output_len) {
  word32 len = output_max_len - 1; // wolfcrypt will add a null byte after the decoded data
  int rc = Base64_Encode_NoNl(data, data_len, (unsigned char *)output, &len);
  if (rc) {
    hml_error("b64 encode failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  output[len] = '\0';
  *output_len = len;
  return HMC_STATUS_OK;
}

static hmc_status hmc_b64_decode(const unsigned char *data, size_t data_len,
                                 unsigned char *output, size_t output_max_len,
                                 size_t *output_len) {
  word32 len = output_max_len - 1; // wolfcrypt will add a null byte after the decoded data
  int rc = Base64_Decode((unsigned char *)data, data_len, output, &len);
  if (rc < 0) {
    hml_error("b64 decode failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }
  *output_len = len;
  output[len] = '\0';

  return HMC_STATUS_OK;
}

static inline int hmc_hex_decode_digit(unsigned char d) {
    switch (d) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      return d - '0';
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
      return d - 'A' + 0xA;
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
      return d - 'a' + 0xA;
    }
    return -1;
}

static hmc_status hmc_hex_decode(const unsigned char *data, size_t data_len,
                                 unsigned char *output,
                                 size_t output_max_len,
                                 size_t *output_len) {
  if (data_len % 2 != 0) {
    hml_error("refusing to decode odd number of hex digits");
    return HMC_STATUS_FAILURE;
  }

  size_t decode_len = data_len / 2;
  if (decode_len > output_max_len) {
    return HMC_STATUS_BUFFER_TOO_SMALL;
  }

  for (size_t i = 0; i < decode_len; ++i) {
    int high = hmc_hex_decode_digit(data[2*i]);
    int low = hmc_hex_decode_digit(data[2*i+1]);
    if (high < 0 || low < 0) {
      hml_error("invalid hex digit");
      return HMC_STATUS_FAILURE;
    }
    output[i] = (uint8_t)((high << 4) | low);
  }

  *output_len = decode_len;

  return HMC_STATUS_OK;
}

static hmc_status hmc_hex_encode(const unsigned char *data, size_t data_len,
                                 unsigned char *output,
                                 size_t output_max_len,
                                 size_t *output_len) {
  size_t encode_len = data_len * 2;
  if (encode_len > output_max_len) {
    return HMC_STATUS_BUFFER_TOO_SMALL;
  }

  for (size_t i = 0; i < data_len; ++i) {
    int high = data[i] >> 4;
    int low = data[i] & 0xf;

    output[i*2] = high < 0xA ? high + '0' : high + 'a' - 0xA;
    output[i*2+1] = low < 0xA ? low + '0' : low + 'a' - 0xA;
  }

  *output_len = encode_len;

  return HMC_STATUS_OK;
}

static hmc_status hmc_generate_kyber_key_pair(
    hmc_key_type key_type, hmc_data_type output_type,
    unsigned char *private_key_output, size_t private_key_output_max_len,
    size_t *private_key_output_len, unsigned char *public_key_output,
    size_t public_key_output_max_len, size_t *public_key_output_len) {
#ifndef NO_KYBER

  KyberKey key;
  hmc_status status;
  WC_RNG rng;
  size_t pub_len;
  size_t priv_len;
  int type;

  switch (key_type) {
  case HMC_KEY_TYPE_KYBER512:
    pub_len = KYBER512_PUBLIC_KEY_SIZE;
    priv_len = KYBER512_PRIVATE_KEY_SIZE;
    type = KYBER512;
    break;
  case HMC_KEY_TYPE_KYBER768:
    pub_len = KYBER768_PUBLIC_KEY_SIZE;
    priv_len = KYBER768_PRIVATE_KEY_SIZE;
    type = KYBER768;
    break;
  case HMC_KEY_TYPE_KYBER1024:
    pub_len = KYBER1024_PUBLIC_KEY_SIZE;
    priv_len = KYBER1024_PRIVATE_KEY_SIZE;
    type = KYBER1024;
    break;
  default:
    return HMC_STATUS_FAILURE;
  }

  int rc = wc_KyberKey_Init(type, &key, NULL, INVALID_DEVID);
  if (rc) {
    hml_error("key init failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    wc_KyberKey_Free(&key);
    return HMC_STATUS_FAILURE;
  }
  rc = wc_KyberKey_MakeKey(&key, &rng);
  if (rc) {
    hml_error("make key failed with %d", rc);
    wc_FreeRng(&rng);
    wc_KyberKey_Free(&key);
    return HMC_STATUS_FAILURE;
  }

  unsigned char pub[pub_len];
  rc = wc_KyberKey_EncodePublicKey(&key, pub, pub_len);
  if (rc) {
    hml_error("key to der failed with %d", rc);
    wc_FreeRng(&rng);
    wc_KyberKey_Free(&key);
    return HMC_STATUS_FAILURE;
  }

  status = hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, pub, pub_len,
                       HMC_HASH_TYPE_NONE, output_type, public_key_output,
                       public_key_output_max_len, public_key_output_len);
  if (status != HMC_STATUS_OK) {
    wc_FreeRng(&rng);
    wc_KyberKey_Free(&key);
    return status;
  }

  unsigned char priv[priv_len];
  rc = wc_KyberKey_EncodePrivateKey(&key, priv, priv_len);
  if (rc) {
    hml_error("key to der failed with %d", rc);
    wc_FreeRng(&rng);
    wc_KyberKey_Free(&key);
    return HMC_STATUS_FAILURE;
  }

  status = hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, priv, priv_len,
                       HMC_HASH_TYPE_NONE, output_type, private_key_output,
                       private_key_output_max_len, private_key_output_len);
  if (status != HMC_STATUS_OK) {
    wc_FreeRng(&rng);
    wc_KyberKey_Free(&key);
    return status;
  }

  wc_FreeRng(&rng);
  wc_KyberKey_Free(&key);
  return HMC_STATUS_OK;
#else
  return HMC_STATUS_FAILURE;
#endif
}

static hmc_status hmc_create_rsa_signature(
    hmc_key_type key_type, hmc_cred_type cred_type, hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *input, size_t input_len, hmc_data_type output_type,
    unsigned char *output, size_t output_max_len, size_t *output_len) {
  RsaKey priv;
  hmc_status status;
  WC_RNG rng;

  if (key_type != HMC_KEY_TYPE_RSA) {
    return HMC_STATUS_FAILURE;
  }
  if (key_data_type == HMC_DATA_TYPE_RAW) {
    key_data_type = HMC_DATA_TYPE_DER;
  }

  status = hmc_read_private_rsa_key(key_data_type, cred_type,
                                    private_key, private_key_len, &priv);
  if (status != HMC_STATUS_OK) {
    hml_error("could not read private key");
    return status;
  }

  int sig_len = wc_SignatureGetSize(WC_SIGNATURE_TYPE_RSA_W_ENC, &priv, sizeof(RsaKey));
  if (sig_len <= 0) {
    wc_FreeRsaKey(&priv);
    return HMC_STATUS_FAILURE;
  }

  int rc = wc_InitRng(&rng);
  if (rc) {
    hml_error("wolfcrypt rng failed with %d", rc);
    wc_FreeRsaKey(&priv);
    return HMC_STATUS_FAILURE;
  }

  unsigned char sig_buf[sig_len];
  word32 sig_buf_len = sig_len;
  rc = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA_W_ENC, input, input_len, sig_buf, &sig_buf_len, &priv, sizeof(RsaKey), &rng);
  wc_FreeRsaKey(&priv);
  wc_FreeRng(&rng);
  if (rc) {
    hml_error("signature generate failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  return hmc_convert(HMC_DATA_TYPE_RAW, HMC_CRED_TYPE_NONE, sig_buf, (size_t) sig_buf_len,
                     HMC_HASH_TYPE_NONE, output_type, output, output_max_len,
                     output_len);
}


#ifdef USE_RDSEED
unsigned long long hmc_generate_seed() {
  unsigned long long value = 0;
  int rc = 0;
  while (rc == 0) {
    rc = _rdseed64_step(&value);
  }
  return value;
}

int getentropy(void *buffer, size_t length) {
  size_t len;
  hmc_generate_random(length, HMC_DATA_TYPE_RAW, buffer, length, &len);
  return 0;
}

#endif
