#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hm_log.h"
#include "hm_sync.h"

typedef enum hmc_status
{
  HMC_STATUS_OK = 0,
  HMC_STATUS_FAILURE = 1,
  HMC_STATUS_BUFFER_TOO_SMALL = 2,
  HMC_STATUS_INVALID_KEY_SIZE = 3,
  HMC_STATUS_CERT_VERIFY_FAILED = 4,
} hmc_status;

typedef enum hmc_data_type
{
  HMC_DATA_TYPE_RAW = 0,
  HMC_DATA_TYPE_BASE64 = 1,
  HMC_DATA_TYPE_BASE64_URLSAFE = 2,
  HMC_DATA_TYPE_BASE64_URLSAFE_NOPADDING = 3,
  HMC_DATA_TYPE_PEM = 4,
  HMC_DATA_TYPE_DER = 5,
  HMC_DATA_TYPE_HEX = 6,
} hmc_data_type;

typedef enum hmc_cred_type
{
  HMC_CRED_TYPE_NONE = 0,
  HMC_CRED_TYPE_PRIVATE_KEY = 1,
  HMC_CRED_TYPE_PUBLIC_KEY = 2,
  HMC_CRED_TYPE_CERT = 3,
  HMC_CRED_TYPE_PKCS8 = 4,
  HMC_CRED_TYPE_RSA_PRIVATE_KEY = 5,
  HMC_CRED_TYPE_RSA_PUBLIC_KEY = 6
} hmc_cred_type;

typedef enum hmc_cert_type
{
  HMC_CERT_TYPE_INTERNAL = 0,
  HMC_CERT_TYPE_EXTERNAL = 1,
} hmc_cert_type;

typedef enum hmc_sig_type
{
  HMC_SIG_TYPE_NONE = 0,
  HMC_SIG_TYPE_CTC_SHA256wECDSA = 1,
  HMC_SIG_TYPE_CTC_SHA384wECDSA = 2,
  HMC_SIG_TYPE_CTC_SHA512wECDSA = 3,
} hmc_sig_type;

typedef enum hmc_sig_format
{
  HMC_SIG_FORMAT_UNKNOWN = 0,
  HMC_SIG_FORMAT_FIXED = 1,
  HMC_SIG_FORMAT_ASN1DER = 2,
} hmc_sig_format;

typedef enum hmc_hash_type
{
  HMC_HASH_TYPE_NONE = 0,
  HMC_HASH_TYPE_SHA256 = 1,
  HMC_HASH_TYPE_SHA384 = 2,
  HMC_HASH_TYPE_SHA256SHA256 = 3,
  HMC_HASH_TYPE_SHA1 = 4, // only for websocket exchange
} hmc_hash_type;

typedef enum hmc_key_type
{
  HMC_KEY_TYPE_NONE = 0,
  HMC_KEY_TYPE_ECC256 = 1,
  HMC_KEY_TYPE_ECC384 = 2,
  HMC_KEY_TYPE_ECC521 = 3,
  HMC_KEY_TYPE_KYBER512 = 4,
  HMC_KEY_TYPE_KYBER768 = 5,
  HMC_KEY_TYPE_KYBER1024 = 6,
  HMC_KEY_TYPE_RSA = 7,
  HMC_KEY_TYPE_RSA3072_E3 = 8 // RSA key with 3072 bits and public exponent of 3
} hmc_key_type;

typedef enum hmc_cert_status
{
  HMC_CERT_STATUS_INVALID = 0,
  HMC_CERT_STATUS_EXPIRED_AND_SELF_SIGNED = 1,
  HMC_CERT_STATUS_EXPIRED = 2,
  HMC_CERT_STATUS_SELF_SIGNED = 3,
  HMC_CERT_STATUS_OK = 4,
} hmc_cert_status;

hmc_status hmc_init(hml_log_cb *logger_function);

hmc_status hmc_generate_key_pair(hmc_key_type key_type, hmc_data_type output_type,
                                 unsigned char *private_key_output, size_t private_key_output_max_len,
                                 size_t *private_key_output_len, unsigned char *public_key_output,
                                 size_t public_key_output_max_len, size_t *public_key_output_len);

hmc_status hmc_generate_random(size_t len, hmc_data_type output_type,
                               unsigned char *output, size_t output_max_len,
                               size_t *output_len);

hmc_status hmc_decrypt_ecc(hmc_data_type key_data_type,
                           const unsigned char *priv_key, size_t priv_key_len,
                           hmc_data_type input_type, const unsigned char *input,
                           size_t input_len, hmc_data_type output_type,
                           unsigned char *output, size_t output_max_len,
                           size_t *output_len);

hmc_status hmc_encrypt_ecc(hmc_data_type key_data_type,
                           const unsigned char *priv_key, size_t priv_key_len,
                           const unsigned char *pub_key, size_t pub_key_len,
                           const unsigned char *input, size_t input_len,
                           hmc_data_type output_type, unsigned char *output,
                           size_t output_max_len, size_t *output_len);

hmc_status hmc_encrypt(hmc_data_type key_data_type,
                       const unsigned char *key, size_t key_len,
                       const unsigned char *input, size_t input_len,
                       const unsigned char *aes, size_t aes_len,
                       hmc_data_type output_type,
                       unsigned char *output, size_t output_max_len,
                       size_t *output_len);

hmc_status hmc_decrypt(hmc_data_type key_data_type, const unsigned char *key,
                       size_t key_len, hmc_data_type input_type,
                       const unsigned char *input, size_t input_len,
                       const unsigned char *aes, size_t aes_len,
                       hmc_data_type output_type, unsigned char *output,
                       size_t output_max_len, size_t *output_len);

hmc_status hmc_concat_kdf(const unsigned char *shared_secret, size_t shared_secret_len,
                          const unsigned char *enc, size_t enc_len,
                          const unsigned char *party_u, size_t party_u_len,
                          const unsigned char *party_v, size_t party_v_len,
                          size_t enc_key_numbits,
                          unsigned char *output, size_t output_len);

hmc_status hmc_derive_key(hmc_data_type key_data_type, const unsigned char *key,
                          size_t key_len, hmc_data_type input_type,
                          const unsigned char *input, size_t input_len,
                          hmc_data_type output_type, unsigned char *output,
                          size_t output_max_len, size_t *output_len);

hmc_status hmc_hmac_sign(hmc_data_type key_data_type, const unsigned char *key,
                          size_t key_len, hmc_data_type input_type,
                          const unsigned char *input, size_t input_len,
                          hmc_hash_type hash_type,
                          hmc_data_type output_type, unsigned char *output,
                          size_t output_max_len, size_t *output_len);

hmc_status hmc_sha256_hmac_writer(hmc_data_type key_data_type, const unsigned char *key,
                                  size_t key_len, void **output_hmac);
hmc_status hmc_update_hmac(void *hmac, const unsigned char *input, size_t input_len);
hmc_status hmc_finalize_sha256_hmac(void *hmac, unsigned char out[32]);
hmc_status hmc_free_hmac_writer(void *hmac);

hmc_status hmc_create_shared_ecc_secret(
    hmc_key_type key_type, hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_data_type output_type, unsigned char *output, size_t output_max_len,
    size_t *output_len);

hmc_status hmc_create_shared_ecc_kyber_hybrid_secret(
    hmc_key_type ecc_key_type, hmc_data_type ecc_key_data_type,
    const unsigned char *ecc_private_key, size_t ecc_private_key_len,
    const unsigned char *ecc_public_key, size_t ecc_public_key_len,
    hmc_data_type kyber_shared_secret_input_type,
    unsigned char *kyber_shared_secret, size_t kyber_shared_secret_len,
    hmc_data_type output_type, unsigned char *output, size_t output_max_len,
    size_t *output_len);

hmc_status hmc_create_shared_ecc_kyber_hybrid_secret(
    hmc_key_type key_type, hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_data_type kyber_shared_secret_input_type,
    unsigned char *kyber_shared_scret, size_t kyber_shared_secret_len,
    hmc_data_type output_type, unsigned char *output, size_t output_max_len,
    size_t *output_len);

hmc_status hmc_create_shared_kyber_secret(
    hmc_key_type key_type, hmc_data_type key_data_type,
    const unsigned char *public_key, size_t public_key_len,
    hmc_data_type output_type, unsigned char *output_secret,
    size_t output_secret_max_len, size_t *output_secret_len,
    unsigned char *output_encrypted_secret,
    size_t output_encrypted_secret_max_len,
    size_t *output_encrypted_secret_len);

hmc_status hmc_decrypt_shared_kyber_secret(
    hmc_key_type key_type, hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    hmc_data_type encrypted_secret_data_type,
    const unsigned char *encrypted_secret, size_t encrypted_secret_len,
    hmc_data_type output_type, unsigned char *output, size_t output_max_len,
    size_t *output_len);

hmc_status
hmc_create_signature(hmc_key_type key_type, hmc_cred_type cred_type, hmc_data_type key_data_type,
                     const unsigned char *private_key, size_t private_key_len,
                     const unsigned char *input, size_t input_len,
                     hmc_data_type output_type, unsigned char *output,
                     size_t output_max_len, size_t *output_len);

hmc_status hmc_verify_signature(hmc_key_type key_type,
                                hmc_data_type key_data_type,
                                const unsigned char *public_key,
                                size_t public_key_len,
                                const unsigned char *input, size_t input_len,
                                hmc_sig_format signature_format,
                                hmc_data_type signature_data_type,
                                const unsigned char *signature,
                                size_t signature_len, bool *verified);

hmc_status hmc_create_certificate(
    const unsigned char *csr, size_t csr_len, hmc_data_type csr_data_type,
    const unsigned char *ca_cert, size_t ca_cert_len,
    hmc_data_type ca_cert_type,
    hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    const unsigned char *public_key, size_t public_key_len,
    hmc_sig_type output_sig_type,
    hmc_data_type output_data_type, unsigned char *output,
    size_t output_max_len, size_t *output_len);

hmc_status hmc_create_certificate_signing_request(
    const char *common_name, size_t common_name_len,
    hmc_key_type key_type, hmc_data_type key_data_type,
    const unsigned char *private_key, size_t private_key_len,
    hmc_sig_type output_sig_type,
    hmc_data_type output_data_type, unsigned char *output,
    size_t output_max_len, size_t *output_len);

hmc_status hmc_convert(hmc_data_type input_type, hmc_cred_type input_cred_type,
                       const unsigned char *input, size_t input_len,
                       hmc_hash_type hash_type, hmc_data_type output_type,
                       unsigned char *output, size_t output_max_len,
                       size_t *output_len);

hmc_status hmc_import_ecc_key_x_y_d(hmc_key_type key_type,
                                    const unsigned char *x, size_t x_len,
                                    const unsigned char *y, size_t y_len,
                                    const unsigned char *d, size_t d_len,
                                    hmc_data_type output_type,
                                    unsigned char *output, size_t output_max_len,
                                    size_t *output_len);

hmc_status hmc_export_ecc_key_x_y(hmc_data_type key_data_type,
                                  const unsigned char *public_key, size_t public_key_len,
                                  const unsigned char *x, size_t x_max_len, size_t *x_len,
                                  const unsigned char *y, size_t y_max_len, size_t *y_len);

hmc_status hmc_export_rsa_key_e_n(hmc_data_type key_data_type,
                                  const unsigned char *public_key, size_t public_key_len,
                                  const unsigned char *e, size_t e_max_len, size_t *e_len,
                                  const unsigned char *n, size_t n_max_len, size_t *n_len);

hmc_status hmc_ecc_key_to_pkcs8(hmc_data_type key_data_type,
                                const unsigned char *private_key, size_t private_key_len,
                                hmc_data_type output_data_type,
                                unsigned char *output, size_t output_max_len, size_t *output_len);

#ifdef USE_RDSEED
unsigned long long hmc_generate_seed();
#endif
