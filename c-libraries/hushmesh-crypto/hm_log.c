#include "hm_log.h"

int hLOGMask = 0xFF;

#define LOG_MESSAGE_MAX_LENGTH 8192

static hml_log_cb *log_cb;

void hml_set_log_cb(hml_log_cb *cb) {
  if (cb) {
    log_cb = cb;
  }
}

void hml_set_level(hml_level level) {
  int i;
  int new_mask = 0;

  for (i = 0; i <= level; i++) {
    new_mask |= 1 << i;
  }
  hLOGMask = new_mask;
}

void hml_log(hml_level level, const char *file, const char *function,
             int line_number, const char *fmt, ...) {
  va_list va;
  char buf[LOG_MESSAGE_MAX_LENGTH + 1];
  int len;
  char *ptr;
  size_t max_len;

  if (!log_cb || !hml_test(level)) {
    return;
  }

  max_len = sizeof(buf) - 4;
  ptr = buf;

  len = snprintf(ptr, max_len, "%s (%d): ", file, line_number);

  if (len <= 0) {
    return;
  }
  len = strlen(ptr);
  max_len -= len;
  ptr += len;

  if (fmt != NULL) {
    va_start(va, fmt);
    len = vsnprintf(ptr, (size_t)max_len, fmt, va);
    va_end(va);

    if (len <= 0) {
      return;
    }

    len = strlen(ptr);
    ptr += len;
    max_len -= len;
  }
  *ptr = '\n';
  ptr++;
  *ptr = '\0';

  log_cb(level, buf);
}

void hml_log_raw(hml_level level, const char *file, const char *function,
             int line_number, const char *fmt, ...) {
  va_list va;
  char buf[LOG_MESSAGE_MAX_LENGTH + 1];
  int len;
  char *ptr;
  size_t max_len;

  if (!log_cb || !hml_test(level)) {
    return;
  }

  max_len = sizeof(buf) - 4;
  ptr = buf;

  len = snprintf(ptr, max_len, "%s (%d): ", file, line_number);

  if (len <= 0) {
    return;
  }
  len = strlen(ptr);
  max_len -= len;
  ptr += len;

  if (fmt != NULL) {
    va_start(va, fmt);
    len = vsnprintf(ptr, (size_t)max_len, fmt, va);
    va_end(va);

    if (len <= 0) {
      return;
    }

    len = strlen(ptr);
    ptr += len;
    max_len -= len;
  }
  *ptr = '\0';

  log_cb(level, buf);
}