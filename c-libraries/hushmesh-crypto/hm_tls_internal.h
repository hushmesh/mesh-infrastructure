#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/ssl.h>

#include "hm_tls.h"

typedef struct hmc_tls_server_context {
  WOLFSSL_CTX *srv_ctx;
} hmc_tls_server_context;

typedef struct hmc_tls_buffer {
  unsigned char *buffer;
  size_t len;
  size_t offset;
  size_t max_len;
} hmc_tls_buffer;

typedef struct hmc_tls_connection {
  WOLFSSL_CTX *client_ctx;
  WOLFSSL *conn;
  hmc_tls_buffer read_buffer;
  hmc_tls_buffer write_buffer;
  bool connect_pending;
  bool accept_pending;
  hmc_cert_type cert_type;
} hmc_tls_connection;
