#pragma once

#ifdef __cplusplus
extern "C" {
#endif


#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum hml_level {
  HML_LEVEL_ERROR = 0,
  HML_LEVEL_INFO = 1,
  HML_LEVEL_DEBUG = 2
} hml_level;

extern int hLOGMask;

#define hml_test(level) ((1 << level) & hLOGMask)

#define hml_debug(fmt, ...)                                                    \
  do {                                                                         \
    if (hml_test(HML_LEVEL_DEBUG)) {                                           \
      hml_log(HML_LEVEL_DEBUG, __FILE__, (char *)__FUNCTION__, __LINE__, fmt,  \
              ##__VA_ARGS__);                                                  \
    }                                                                          \
  } while (0)
#define hml_info(fmt, ...)                                                     \
  do {                                                                         \
    if (hml_test(HML_LEVEL_INFO)) {                                            \
      hml_log(HML_LEVEL_INFO, __FILE__, (char *)__FUNCTION__, __LINE__, fmt,   \
              ##__VA_ARGS__);                                                  \
    }                                                                          \
  } while (0)
#define hml_error(fmt, ...)                                                    \
  do {                                                                         \
    if (hml_test(HML_LEVEL_ERROR)) {                                           \
      hml_log(HML_LEVEL_ERROR, __FILE__, (char *)__FUNCTION__, __LINE__, fmt,  \
              ##__VA_ARGS__);                                                  \
    }                                                                          \
  } while (0)

#define hml_debug_raw(fmt, ...)                                                    \
  do {                                                                             \
    if (hml_test(HML_LEVEL_DEBUG)) {                                               \
      hml_log_raw(HML_LEVEL_DEBUG, __FILE__, (char *)__FUNCTION__, __LINE__, fmt,  \
              ##__VA_ARGS__);                                                      \
    }                                                                              \
  } while (0)
#define hml_info_raw(fmt, ...)                                                     \
  do {                                                                             \
    if (hml_test(HML_LEVEL_INFO)) {                                                \
      hml_log_raw(HML_LEVEL_INFO, __FILE__, (char *)__FUNCTION__, __LINE__, fmt,   \
              ##__VA_ARGS__);                                                      \
    }                                                                              \
  } while (0)
#define hml_error_raw(fmt, ...)                                                    \
  do {                                                                             \
    if (hml_test(HML_LEVEL_ERROR)) {                                               \
      hml_log_raw(HML_LEVEL_ERROR, __FILE__, (char *)__FUNCTION__, __LINE__, fmt,  \
              ##__VA_ARGS__);                                                      \
    }                                                                              \
  } while (0)

void hml_set_level(hml_level level);
void hml_log(hml_level level, const char *file, const char *function,
             int line_number, const char *fmt, ...)
  __attribute__ ((format (printf, 5, 6))); // enable printf warnings
void hml_log_raw(hml_level level, const char *file, const char *function,
             int line_number, const char *fmt, ...);
typedef void hml_log_cb(hml_level level, char *buf);
void hml_set_log_cb(hml_log_cb *cb);

#ifdef __cplusplus
}
#endif
