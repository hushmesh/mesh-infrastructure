#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hm_crypt.h"
#include "hm_log.h"

typedef void *hmc_tls_server_handle;
typedef void *hmc_tls_connection_handle;

hmc_status hmc_tls_init(hml_log_cb *logger_function);

hmc_status hmc_tls_init_no_log();

/* note: rust caller is responsible for locking around functions to provide
 * thread safety, e.g. a lock per hmc_tls_connection_handle  */

hmc_status
hmc_tls_server_init(hmc_tls_server_handle *server,
                    const unsigned char *private_key_pem, size_t private_key_len,
                    const unsigned char *certificate_pem, size_t certificate_len,
                    hmc_cert_type cert_type);

hmc_status hmc_tls_server_new_connection(hmc_tls_server_handle server,
                                         hmc_key_type key_type,
                                         hmc_tls_connection_handle *conn,
                                         hmc_cert_type cert_type);

hmc_status hmc_tls_process_data(hmc_tls_connection_handle conn,
                                const unsigned char *data, size_t data_len,
                                size_t *amount_read);

hmc_status hmc_tls_read(hmc_tls_connection_handle conn, unsigned char *buffer,
                        size_t max_len, size_t *amount_read);

bool hmc_tls_read_pending(hmc_tls_connection_handle conn);

size_t hmc_tls_read_pending_size(hmc_tls_connection_handle conn);

hmc_status hmc_tls_write(hmc_tls_connection_handle conn,
                         const unsigned char *data, size_t data_len,
                         size_t *amount_written);

hmc_status hmc_tls_get_send_data(hmc_tls_connection_handle conn,
                                 unsigned char *buffer, size_t max_len,
                                 size_t *len);

bool hmc_tls_write_pending(hmc_tls_connection_handle conn);

bool hmc_tls_connect_pending(hmc_tls_connection_handle conn);

size_t hmc_tls_write_pending_size(hmc_tls_connection_handle conn);

hmc_status hmc_tls_close_connection(hmc_tls_connection_handle conn);
hmc_status hmc_tls_server_destroy(hmc_tls_server_handle server);

hmc_status hmc_tls_client_new_connection(const char *host,
                                         hmc_data_type key_data_type,
                                         const unsigned char *ca_cert,
                                         size_t ca_cert_len,
                                         hmc_tls_connection_handle *conn,
                                         bool check_domain_name,
                                         hmc_cert_type remote_cert_type);
