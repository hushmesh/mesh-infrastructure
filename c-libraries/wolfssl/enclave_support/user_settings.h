#ifndef _USER_SETTINGS_H_
#define _USER_SETTINGS_H_

extern unsigned long long hmc_generate_seed();

#define CUSTOM_RAND_GENERATE hmc_generate_seed
#define CUSTOM_RAND_TYPE unsigned long long

/* Enable options */
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ECC
#define HAVE_SUPPORTED_CURVES
#define HAVE_TLS_EXTENSIONS
#define HAVE_ONE_TIME_AUTH
#define HAVE_TRUNCATED_HMAC
#define HAVE_EXTENDED_MASTER
#define HAVE_ALPN
#define HAVE_SNI
#define HAVE_OCSP
#define HAVE_AESGCM
#define HAVE_HKDF /*rsc*/
#define HAVE_ECC_ENCRYPT /*rsc*/
#define WOLFSSL_KEY_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_EXT
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_PUB_PEM_TO_DER
#define WOLFSSL_DER_TO_PEM
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_BASE64_ENCODE
#define WOLFSSL_USER_IO
#define WOLFSSL_TLS13
#define HAVE_LIBOQS
#define WOLFSSL_EXPERIMENTAL_SETTINGS

#define WC_RSA_PSS
#define WC_RSA_BLINDING
#define HAVE_FFDHE_2048
#define SP_INT_BITS 4096
#define HAVE_FFDHE_3072
#define HAVE_FFDHE_4096
/*
#define HAVE_FFDHE_6144 
#define HAVE_FFDHE_8192
*/
#define HAVE_PUBLIC_FFDHE

/* Disable options */
#define NO_PWDBASED
#define NO_DSA
#define NO_DES3
#define NO_RABBIT
#define NO_RC4
#define NO_MD4

#endif /* _USER_SETTINGS_H_ */
