#include <wolfssl/options.h>

#include "hm_tls_internal.h"
#include <wolfssl/error-ssl.h>

#define TLS_BUFFER_SIZE (64 * 1024)
#define EXTERNAL_CIPHER_SUITES "TLS13-AES256-GCM-SHA384"\
                              ":ECDHE-ECDSA-AES256-GCM-SHA384"\
                              ":ECDHE-RSA-AES256-GCM-SHA384"\
                              ":ECDHE-ECDSA-AES128-GCM-SHA256"\
                              ":ECDHE-RSA-AES128-GCM-SHA256"
#define INTERNAL_CIPHER_SUITES "TLS13-AES256-GCM-SHA384"

// sets the list of elliptic curve groups in order of preference (highest to lowest)
static int client_external_ecc_groups[] = {
  WOLFSSL_ECC_SECP521R1,
  WOLFSSL_ECC_SECP384R1,
  WOLFSSL_ECC_SECP256R1
};

// When the remote certificate type is internal (see hmc_cert_type), the client will
// use post-quantum hybrid key exchange algorithms.
static int client_internal_ecc_groups[] = {
  WOLFSSL_P521_KYBER_LEVEL5,
  WOLFSSL_P384_KYBER_LEVEL3,
  WOLFSSL_P256_KYBER_LEVEL1,
};

static int mInit = false;
static int hmc_tls_send(WOLFSSL *ssl, char *buf, int sz, void *ctx);
static int hmc_tls_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
static void hmc_free_buffer(hmc_tls_buffer *buffer);
static size_t hmc_append_buffer(hmc_tls_buffer *buffer,
                                const unsigned char *data, size_t data_len);
static size_t hmc_move_buffer(hmc_tls_buffer *buffer, unsigned char *data,
                              size_t data_len);
static bool hmc_buffer_empty(hmc_tls_buffer *buffer);
static size_t hmc_buffer_pending_size(hmc_tls_buffer *buffer);

hmc_status hmc_tls_init_no_log() { return hmc_tls_init(NULL); }

hmc_status hmc_tls_init(hml_log_cb *logger_function) {
  if (mInit) {
    return HMC_STATUS_OK;
  }

  hml_set_log_cb(logger_function);
  int rc = wolfSSL_Init();
  if (rc != WOLFSSL_SUCCESS) {
    hml_error("wolfssl init failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  mInit = true;
  return HMC_STATUS_OK;
}

hmc_status
hmc_tls_server_init(hmc_tls_server_handle *server,
                    const unsigned char *private_key_pem, size_t private_key_len,
                    const unsigned char *certificate_pem, size_t certificate_len,
                    hmc_cert_type cert_type) {
  hmc_tls_server_context *server_ctx;
  WOLFSSL_CTX *ctx;
  int format = SSL_FILETYPE_PEM;
  int rc;

  if (private_key_pem[private_key_len - 1] != 0) {
    hml_error("private_key_pem is not a valid C string");
    return HMC_STATUS_FAILURE;
  }

  if (certificate_pem[certificate_len - 1] != 0) {
    hml_error("certificate_pem is not a valid C string");
    return HMC_STATUS_FAILURE;
  }

  *server = NULL;
  ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());

  if (!ctx) {
    hml_error("could not create server context");
    return HMC_STATUS_FAILURE;
  }

  if (wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2) != WOLFSSL_SUCCESS) {
    hml_error("failed to set version");
    return HMC_STATUS_FAILURE;
  }

  if (cert_type == HMC_CERT_TYPE_INTERNAL) {
    rc = wolfSSL_CTX_set_cipher_list(ctx, INTERNAL_CIPHER_SUITES);
  } else if (cert_type == HMC_CERT_TYPE_EXTERNAL) {
    rc = wolfSSL_CTX_set_cipher_list(ctx, EXTERNAL_CIPHER_SUITES);
  } else {
    wolfSSL_CTX_free(ctx);
    hml_error("unknown cert type %d", cert_type);
    return HMC_STATUS_FAILURE;
  }

  if (rc != WOLFSSL_SUCCESS) {
    wolfSSL_CTX_free(ctx);
    hml_error("could not set cipher list (%d)", rc);
    return HMC_STATUS_FAILURE;
  }

  rc = wolfSSL_CTX_use_PrivateKey_buffer(ctx, private_key_pem, private_key_len,
                                         format);
  if (rc != WOLFSSL_SUCCESS) {
    hml_error("load private key failed with %d", rc);
    wolfSSL_CTX_free(ctx);
    return HMC_STATUS_FAILURE;
  }

  bool is_chain = false;
  // strnstr is not available in sgx
  char *begin = strstr((const char*) certificate_pem, "-BEGIN");
  if (begin) {
    is_chain = strstr(begin + 6, "-BEGIN") != NULL;
  }
  if (is_chain) {
    rc = wolfSSL_CTX_use_certificate_chain_buffer(ctx, certificate_pem,
                                                  certificate_len);
  } else {
    rc = wolfSSL_CTX_use_certificate_buffer(ctx, certificate_pem, certificate_len,
                                            format);
  }
  if (rc != WOLFSSL_SUCCESS) {
    hml_error("load certificate failed with %d", rc);
    wolfSSL_CTX_free(ctx);
    return HMC_STATUS_FAILURE;
  }

  wolfSSL_CTX_SetIOSend(ctx, hmc_tls_send);
  wolfSSL_CTX_SetIORecv(ctx, hmc_tls_recv);

  server_ctx =
      (hmc_tls_server_context *)calloc(sizeof(hmc_tls_server_context), 1);
  server_ctx->srv_ctx = ctx;
  *server = server_ctx;
  return HMC_STATUS_OK;
}

static void hmc_debug_cipher_suite(WOLFSSL *ssl_conn, hmc_cert_type cert_type) {
  const char* cipher_name = wolfSSL_get_cipher(ssl_conn);
  if (!cipher_name) {
    hml_error("connection using unknown cipher suite");
  } else {
    const char *cert_type_s = (cert_type == HMC_CERT_TYPE_INTERNAL) ? "internal" : "external";
    hml_debug_raw("%s connection using cipher suite %s", cert_type_s, cipher_name);
  }
}

hmc_status hmc_tls_client_new_connection(const char *host,
                                         hmc_data_type key_data_type,
                                         const unsigned char *ca_cert,
                                         size_t ca_cert_len,
                                         hmc_tls_connection_handle *conn,
                                         bool check_domain_name,
                                         hmc_cert_type remote_cert_type) {
  hmc_tls_connection *tls_conn;
  WOLFSSL *ssl_conn;
  WOLFSSL_CTX *ctx;
  int rc;
  int format;
  int group_count;
  int *client_ecc_groups;

  if (remote_cert_type == HMC_CERT_TYPE_INTERNAL) {
    client_ecc_groups = client_internal_ecc_groups;
    group_count = sizeof(client_internal_ecc_groups) / sizeof(client_internal_ecc_groups[0]);
  } else if (remote_cert_type == HMC_CERT_TYPE_EXTERNAL) {
    client_ecc_groups = client_external_ecc_groups;
    group_count = sizeof(client_external_ecc_groups) / sizeof(client_external_ecc_groups[0]);
  } else {
    hml_error("unknown remote cert type %d", remote_cert_type);
    return HMC_STATUS_FAILURE;
  }

  switch (key_data_type) {
  case HMC_DATA_TYPE_PEM:
    format = SSL_FILETYPE_PEM;
    break;
  case HMC_DATA_TYPE_DER:
    format = SSL_FILETYPE_ASN1;
    break;
  default:
    hml_error("Invalid format");
    return HMC_STATUS_FAILURE;
  }

  ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
  if (!ctx) {
    hml_error("could not create ssl context");
    return HMC_STATUS_FAILURE;
  }

  if (remote_cert_type == HMC_CERT_TYPE_INTERNAL) {
    rc = wolfSSL_CTX_set_cipher_list(ctx, INTERNAL_CIPHER_SUITES);
  } else if (remote_cert_type == HMC_CERT_TYPE_EXTERNAL) {
    rc = wolfSSL_CTX_set_cipher_list(ctx, EXTERNAL_CIPHER_SUITES);
  } else {
    wolfSSL_CTX_free(ctx);
    hml_error("unknown remote cert type %d", remote_cert_type);
    return HMC_STATUS_FAILURE;
  }

  if (rc != WOLFSSL_SUCCESS) {
    wolfSSL_CTX_free(ctx);
    hml_error("could not set cipher list (%d)", rc);
    return HMC_STATUS_FAILURE;
  }

  wolfSSL_CTX_SetIOSend(ctx, hmc_tls_send);
  wolfSSL_CTX_SetIORecv(ctx, hmc_tls_recv);

  if (ca_cert && ca_cert_len) {
    rc = wolfSSL_CTX_load_verify_buffer(ctx, ca_cert, ca_cert_len, format);
    if (rc != WOLFSSL_SUCCESS) {
      wolfSSL_CTX_free(ctx);
      hml_error("could not load ca data (%d)", rc);
      return HMC_STATUS_FAILURE;
    }
  }

#ifdef HAVE_SNI
  if (wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, host,
                         strlen(host)) != WOLFSSL_SUCCESS) {
    wolfSSL_CTX_free(ctx);
    hml_error("use sni failed");
    return HMC_STATUS_FAILURE;
  }
#endif

  if (ca_cert && ca_cert_len) {
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_DEFAULT, NULL);
  } else {
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
  }

  ssl_conn = wolfSSL_new(ctx);
  if (!ssl_conn) {
    wolfSSL_CTX_free(ctx);
    hml_error("could not create connection context");
    return HMC_STATUS_FAILURE;
  }

  for(int i = 0; i < group_count; i++) {
    rc = wolfSSL_UseKeyShare(ssl_conn, client_ecc_groups[i]);
    if (rc != WOLFSSL_SUCCESS) {
      hml_error("group %d set use key share failed with %d", i, rc);
      wolfSSL_free(ssl_conn);
      wolfSSL_CTX_free(ctx);
      return HMC_STATUS_FAILURE;
    }
  }

  rc = wolfSSL_set_groups(ssl_conn, client_ecc_groups, group_count);
  if (rc != WOLFSSL_SUCCESS) {
    hml_error("set groups failed with %d", rc);
    wolfSSL_free(ssl_conn);
    wolfSSL_CTX_free(ctx);
    return HMC_STATUS_FAILURE;
  }

  if (check_domain_name) {
    rc = wolfSSL_check_domain_name(ssl_conn, host);
    if (rc != WOLFSSL_SUCCESS) {
      hml_error("set check domain failed with %d", rc);
      wolfSSL_free(ssl_conn);
      wolfSSL_CTX_free(ctx);
      return HMC_STATUS_FAILURE;
    }
  }

  tls_conn = (hmc_tls_connection *)calloc(sizeof(hmc_tls_connection), 1);
  tls_conn->conn = ssl_conn;
  tls_conn->client_ctx = ctx;
  tls_conn->cert_type = remote_cert_type;

  wolfSSL_SetIOReadCtx(ssl_conn, tls_conn);
  wolfSSL_SetIOWriteCtx(ssl_conn, tls_conn);

  rc = wolfSSL_connect(ssl_conn);
  if (rc != WOLFSSL_SUCCESS) {
    int error = wolfSSL_get_error(ssl_conn, rc);
    if (error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE) {
      *conn = tls_conn;
      tls_conn->connect_pending = true;
      return HMC_STATUS_OK;
    }
    hmc_tls_close_connection((hmc_tls_connection_handle)tls_conn);
    hml_error("ssl connect failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  hmc_debug_cipher_suite(ssl_conn, remote_cert_type);

  *conn = tls_conn;
  return HMC_STATUS_OK;
}

hmc_status hmc_tls_server_new_connection(hmc_tls_server_handle server,
                                         hmc_key_type key_type,
                                         hmc_tls_connection_handle *conn,
                                         hmc_cert_type cert_type) {
  hmc_tls_connection *tls_conn;
  WOLFSSL *ssl_conn;
  hmc_tls_server_context *ctx = (hmc_tls_server_context *)server;
  int rc;
  int server_ecc_groups[1];
  int group_count = sizeof(server_ecc_groups) / sizeof(server_ecc_groups[0]);

  ssl_conn = wolfSSL_new(ctx->srv_ctx);
  if (!ssl_conn) {
    hml_error("could not create connection context");
    return HMC_STATUS_FAILURE;
  }

  if (cert_type == HMC_CERT_TYPE_INTERNAL) {
    switch (key_type) {
      case HMC_KEY_TYPE_RSA:
        hml_error("internal rsa certificates are not allowed");
        wolfSSL_free(ssl_conn);
        return HMC_STATUS_FAILURE;
      case HMC_KEY_TYPE_ECC256:
        server_ecc_groups[0] = WOLFSSL_P256_KYBER_LEVEL1;
        break;
      case HMC_KEY_TYPE_ECC384:
        server_ecc_groups[0] = WOLFSSL_P384_KYBER_LEVEL3;
        break;
      case HMC_KEY_TYPE_ECC521:
        server_ecc_groups[0] = WOLFSSL_P521_KYBER_LEVEL5;
        break;
      default:
        hml_error("unknown key type %d", key_type);
        wolfSSL_free(ssl_conn);
        return HMC_STATUS_FAILURE;
    }
  } else if (cert_type == HMC_CERT_TYPE_EXTERNAL) {
    switch (key_type) {
      case HMC_KEY_TYPE_RSA:
        group_count = 0;
        break;
      case HMC_KEY_TYPE_ECC256:
        server_ecc_groups[0] = WOLFSSL_ECC_SECP256R1;
        break;
      case HMC_KEY_TYPE_ECC384:
        server_ecc_groups[0] = WOLFSSL_ECC_SECP384R1;
        break;
      case HMC_KEY_TYPE_ECC521:
        server_ecc_groups[0] = WOLFSSL_ECC_SECP521R1;
        break;
      default:
        hml_error("unknown key type %d", key_type);
        wolfSSL_free(ssl_conn);
        return HMC_STATUS_FAILURE;
    }
  } else {
    hml_error("unknown cert type %d", cert_type);
    wolfSSL_free(ssl_conn);
    return HMC_STATUS_FAILURE;
  }
  if (group_count > 0) {
    for (int i = 0; i < group_count; i++) {
      int group = server_ecc_groups[i];
      rc = wolfSSL_UseKeyShare(ssl_conn, group);
      if (rc != WOLFSSL_SUCCESS) {
        hml_error("group %d set use key share failed with %d", group, rc);
        wolfSSL_free(ssl_conn);
        return HMC_STATUS_FAILURE;
      }
    }
    rc = wolfSSL_set_groups(ssl_conn, server_ecc_groups, group_count);
    if (rc != WOLFSSL_SUCCESS) {
      hml_error("set groups failed with %d", rc);
      wolfSSL_free(ssl_conn);
      return HMC_STATUS_FAILURE;
    }
  }

  tls_conn = (hmc_tls_connection *)calloc(sizeof(hmc_tls_connection), 1);
  tls_conn->conn = ssl_conn;
  tls_conn->cert_type = cert_type;

  wolfSSL_SetIOReadCtx(ssl_conn, tls_conn);
  wolfSSL_SetIOWriteCtx(ssl_conn, tls_conn);

  rc = wolfSSL_accept(ssl_conn);
  if (rc != WOLFSSL_SUCCESS) {
    int error = wolfSSL_get_error(ssl_conn, rc);
    if (error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE) {
      *conn = tls_conn;
      tls_conn->accept_pending = true;
      return HMC_STATUS_OK;
    }
    hmc_tls_close_connection((hmc_tls_connection_handle)tls_conn);
    hml_error("ssl accept failed with %d", rc);
    return HMC_STATUS_FAILURE;
  }

  *conn = tls_conn;
  return HMC_STATUS_OK;
}

hmc_status hmc_tls_process_data(hmc_tls_connection_handle conn,
                                const unsigned char *data, size_t data_len,
                                size_t *amount_read) {
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)conn;

  size_t len = hmc_append_buffer(&tls_conn->read_buffer, data, data_len);
  *amount_read = len;

  return HMC_STATUS_OK;
}

bool hmc_tls_read_pending(hmc_tls_connection_handle conn) {
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)conn;

  return !hmc_buffer_empty(&tls_conn->read_buffer) ||
         wolfSSL_want_read(tls_conn->conn);
}

size_t hmc_tls_read_pending_size(hmc_tls_connection_handle conn) {
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)conn;
  return hmc_buffer_pending_size(&tls_conn->read_buffer);
}

hmc_status hmc_tls_read(hmc_tls_connection_handle conn, unsigned char *buffer,
                        size_t max_len, size_t *amount_read) {
  int rc;
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)conn;

  *amount_read = 0;

  if (tls_conn->connect_pending) {
    rc = wolfSSL_connect(tls_conn->conn);
    if (rc != WOLFSSL_SUCCESS) {
      int error = wolfSSL_get_error(tls_conn->conn, rc);
      if (error == WOLFSSL_ERROR_WANT_READ ||
          error == WOLFSSL_ERROR_WANT_WRITE) {
        return HMC_STATUS_OK;
      }
      char buf[256];
      wolfSSL_ERR_error_string_n(error, buf, sizeof(buf));
      hml_error("ssl connect failed with (%d) %s", error, buf);
      switch (error) {
        case DOMAIN_NAME_MISMATCH:
        case VERIFY_CERT_ERROR:
        case ASN_NO_SIGNER_E:
          return HMC_STATUS_CERT_VERIFY_FAILED;
        default:
          return HMC_STATUS_FAILURE;
      }
    }

    tls_conn->connect_pending = false;
    hmc_debug_cipher_suite(tls_conn->conn, tls_conn->cert_type);
  }

  if (tls_conn->accept_pending) {
    rc = wolfSSL_accept(tls_conn->conn);
    if (rc != WOLFSSL_SUCCESS) {
      int error = wolfSSL_get_error(tls_conn->conn, rc);
      if (error == WOLFSSL_ERROR_WANT_READ ||
          error == WOLFSSL_ERROR_WANT_WRITE) {
        return HMC_STATUS_OK;
      }
      char buf[256];
      wolfSSL_ERR_error_string_n(error, buf, sizeof(buf));
      hml_error("ssl accept failed with (%d) %s", error, buf);
      return HMC_STATUS_FAILURE;
    }

    tls_conn->accept_pending = false;
  }


  rc = wolfSSL_read(tls_conn->conn, buffer, max_len);
  if (rc > 0) {
    *amount_read = (size_t)rc;
    return HMC_STATUS_OK;
  }

  int err = wolfSSL_get_error(tls_conn->conn, rc);

  if ((err == WOLFSSL_ERROR_WANT_READ) || (err == WOLFSSL_ERROR_WANT_WRITE) ||
      (err == WOLFSSL_ERROR_ZERO_RETURN)) {
    return HMC_STATUS_OK;
  }

  hml_error("ssl read failed with %d", err);
  return HMC_STATUS_FAILURE;
}

hmc_status hmc_tls_write(hmc_tls_connection_handle conn,
                         const unsigned char *data, size_t data_len,
                         size_t *amount_written) {

  int rc;
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)conn;

  if (tls_conn->connect_pending) {
    hml_error("ssl connection is not complete");
    return HMC_STATUS_FAILURE;
  }
  *amount_written = 0;
  rc = wolfSSL_write(tls_conn->conn, data, data_len);
  if (rc > 0) {
    *amount_written = (size_t)rc;
    return HMC_STATUS_OK;
  }

  int err = wolfSSL_get_error(tls_conn->conn, rc);
  if ((err == WOLFSSL_ERROR_WANT_READ) || (err == WOLFSSL_ERROR_WANT_WRITE)) {
    return HMC_STATUS_OK;
  }

  hml_error("ssl write failed with %d", err);
  return HMC_STATUS_FAILURE;
}

hmc_status hmc_tls_get_send_data(hmc_tls_connection_handle conn,
                                 unsigned char *buffer, size_t max_len,
                                 size_t *len) {
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)conn;

  size_t len_moved = hmc_move_buffer(&tls_conn->write_buffer, buffer, max_len);
  *len = len_moved;
  return HMC_STATUS_OK;
}

bool hmc_tls_write_pending(hmc_tls_connection_handle conn) {
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)conn;

  return !hmc_buffer_empty(&tls_conn->write_buffer) ||
         wolfSSL_want_write(tls_conn->conn);
}

bool hmc_tls_connect_pending(hmc_tls_connection_handle conn) {
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)conn;
  return tls_conn->connect_pending;
}

size_t hmc_tls_write_pending_size(hmc_tls_connection_handle conn) {
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)conn;
  return hmc_buffer_pending_size(&tls_conn->write_buffer);
}

hmc_status hmc_tls_close_connection(hmc_tls_connection_handle conn) {
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)conn;

  if (tls_conn->conn) {
    wolfSSL_free(tls_conn->conn);
  }
  if (tls_conn->client_ctx) {
    wolfSSL_CTX_free(tls_conn->client_ctx);
  }

  hmc_free_buffer(&tls_conn->read_buffer);
  hmc_free_buffer(&tls_conn->write_buffer);
  free(tls_conn);
  return HMC_STATUS_OK;
}

hmc_status hmc_tls_server_destroy(hmc_tls_server_handle server) {
  hmc_tls_server_context *server_ctx = (hmc_tls_server_context *)server;
  if (server_ctx->srv_ctx) {
    wolfSSL_CTX_free(server_ctx->srv_ctx);
  }
  free(server_ctx);
  return HMC_STATUS_OK;
}

static int hmc_tls_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)ctx;
  size_t len = hmc_append_buffer(&tls_conn->write_buffer,
                                 (const unsigned char *)buf, (size_t)sz);
  if (sz && !len) {
    return WOLFSSL_CBIO_ERR_WANT_WRITE;
  }
  return (int)len;
}

static int hmc_tls_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  hmc_tls_connection *tls_conn = (hmc_tls_connection *)ctx;
  size_t len =
      hmc_move_buffer(&tls_conn->read_buffer, (unsigned char *)buf, (size_t)sz);
  if (sz && !len) {
    return WOLFSSL_CBIO_ERR_WANT_READ;
  }
  return (int)len;
}

static void hmc_free_buffer(hmc_tls_buffer *buffer) {
  if (buffer->buffer) {
    free(buffer->buffer);
  }
}

static size_t hmc_append_buffer(hmc_tls_buffer *buffer,
                                const unsigned char *data, size_t data_len) {

  if (!buffer->buffer) {
    buffer->max_len = TLS_BUFFER_SIZE;
    buffer->buffer = malloc(buffer->max_len);
  }

  size_t append_len = data_len;
  size_t left = buffer->max_len - buffer->len;
  if (append_len > left) {
    if (buffer->offset) {
      // tbd - have pool of buffers instead of doing memmove
      size_t used = buffer->len - buffer->offset;
      memmove(buffer->buffer + buffer->offset, buffer->buffer, used);
      buffer->offset = 0;
      buffer->len = used;
      left = buffer->max_len - buffer->len;
      if (append_len > left) {
        append_len = left;
      }
    } else {
      append_len = left;
    }
  }

  memcpy(buffer->buffer + buffer->len, data, append_len);
  buffer->len += append_len;
  return append_len;
}

static size_t hmc_move_buffer(hmc_tls_buffer *buffer, unsigned char *data,
                              size_t data_len) {
  if (!buffer->buffer) {
    return 0;
  }
  size_t move_size = buffer->len - buffer->offset;
  bool all_data = true;
  if (move_size > data_len) {
    move_size = data_len;
    all_data = false;
  }
  memcpy(data, buffer->buffer + buffer->offset, move_size);
  if (all_data) {
    buffer->offset = 0;
    buffer->len = 0;
  } else {
    buffer->offset += move_size;
  }
  return move_size;
}

static bool hmc_buffer_empty(hmc_tls_buffer *buffer) {
  return buffer->len > buffer->offset;
}

static size_t hmc_buffer_pending_size(hmc_tls_buffer *buffer) {
  return buffer->len - buffer->offset;
}
