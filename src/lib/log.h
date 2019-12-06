/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2016-2018 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#pragma once

#define _GNU_SOURCE

#include <stdio.h>

typedef enum {
        CBM_LOG_DEBUG = 0,
        CBM_LOG_INFO,
        CBM_LOG_SUCCESS,
        CBM_LOG_ERROR,
        CBM_LOG_WARNING,
        CBM_LOG_FATAL,
        CBM_LOG_MAX /* Unused */
} CbmLogLevel;

/**
 * Re-initialise the logging functionality, to use a different file descriptor
 * for logging
 *
 * @note This is already called once with stderr as the log file
 */
void cbm_log_init(FILE *log);

/**
 * Log current status/error to stderr. It is recommended to use the
 * macros to achieve this.
 */
void cbm_log(CbmLogLevel level, const char *file, int line, const char *format, ...)
    __attribute__((format(printf, 4, 5)));

/**
 * Log a simple debug message
 */
#define LOG_DEBUG(...) (cbm_log(CBM_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__))

/**
 * Log an informational message
 */
#define LOG_INFO(...) (cbm_log(CBM_LOG_INFO, __FILE__, __LINE__, __VA_ARGS__))

/**
 * Log success
 */
#define LOG_SUCCESS(...) (cbm_log(CBM_LOG_SUCCESS, __FILE__, __LINE__, __VA_ARGS__))

/**
 * Log a non-fatal error
 */
#define LOG_ERROR(...) (cbm_log(CBM_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__))

/**
 * Log a fatal error
 */
#define LOG_FATAL(...) (cbm_log(CBM_LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__))

/**
 * Log a warning message that must always be seen
 */
#define LOG_WARNING(...) (cbm_log(CBM_LOG_WARNING, __FILE__, __LINE__, __VA_ARGS__))

#define check_common_ret_val(level, exp, ret_val, ...)                  \
  do {                                                                  \
          if (exp) {                                                    \
                  LOG_##level(__VA_ARGS__);                             \
                  return ret_val;                                       \
          }                                                             \
  } while(false)                                                        \

#define check_common_ret(level, exp, ...)                       \
        do {                                                    \
                if (exp) {                                      \
                        LOG_##level(__VA_ARGS__);               \
                        return;                                 \
                }                                               \
        } while(false)                                          \

#define check_common_goto(level, exp, label, ...)               \
        do {                                                    \
                if (exp) {                                      \
                        LOG_##level(__VA_ARGS__);               \
                        goto label;                             \
                }                                               \
        } while(false)                                          \

#define check_common_continue(level, exp, ...)                  \
        if (exp) {                                              \
                LOG_##level(__VA_ARGS__);                       \
                continue;                                       \
        }                                                       \

#define check_common(level, exp, ...)                                   \
  do {                                                                  \
          if (exp) {                                                    \
                  LOG_##level(__VA_ARGS__);                             \
          }                                                             \
  } while(false)                                                        \

#define CHECK_ERR(exp, ...)                   \
        check_common(ERROR, exp, __VA_ARGS__) \

#define CHECK_ERR_RET_VAL(exp, ret_val, ...)                     \
        check_common_ret_val(ERROR, exp, ret_val, __VA_ARGS__)   \

#define CHECK_ERR_RET(exp, ...)                           \
        check_common_ret(ERROR, exp, __VA_ARGS__)         \

#define CHECK_ERR_GOTO(exp, label, ...)                           \
        check_common_goto(ERROR, exp, label, __VA_ARGS__)         \

#define CHECK_ERR_CONTINUE(exp, ...)                              \
        check_common_continue(ERROR, exp, __VA_ARGS__)            \

#define CHECK_WARN(exp, ...)                    \
        check_common(WARNING, exp, __VA_ARGS__) \

#define CHECK_WARN_RET_VAL(exp, ret_val, ...)                           \
        check_common_ret_val(WARNING, exp, ret_val, __VA_ARGS__)        \

#define CHECK_WARN_RET(exp, ...)                           \
        check_common_ret(WARNING, exp, __VA_ARGS__)        \

#define CHECK_WARN_GOTO(exp, label, ...)                                \
        check_common_goto(WARNING, exp, label, __VA_ARGS__)             \

#define CHECK_WARN_CONTINUE(exp, ...)                                   \
        check_common_continue(WARNING, exp, __VA_ARGS__)                \

#define CHECK_INF(exp, ...)                     \
        check_common(INFO, exp, __VA_ARGS__)    \

#define CHECK_INF_RET_VAL(exp, ret_val, ...)                            \
        check_common_ret_val(INFO, exp, ret_val, __VA_ARGS__)           \

#define CHECK_INF_RET(exp, ...)                          \
        check_common_ret(INFO, exp, __VA_ARGS__)         \

#define CHECK_INF_GOTO(exp, label, ...)                          \
        check_common_goto(INFO, exp, label, __VA_ARGS__)         \

#define CHECK_INF_CONTINUE(exp, ...)                             \
        check_common_continue(INFO, exp, __VA_ARGS__)            \

#define CHECK_DBG(exp, ...)                      \
        check_common(DEBUG, exp, __VA_ARGS__)    \

#define CHECK_DBG_RET_VAL(exp, ret_val, ...)                            \
        check_common_ret_val(DEBUG, exp, ret_val, __VA_ARGS__)          \

#define CHECK_DBG_RET(exp, ...)                           \
        check_common_ret(DEBUG, exp, __VA_ARGS__)         \

#define CHECK_DBG_GOTO(exp, label, ...)                           \
        check_common_goto(DEBUG, exp, label, __VA_ARGS__)         \

#define CHECK_DBG_CONTINUE(exp, ...)                              \
        check_common_continue(DEBUG, exp, __VA_ARGS__)            \

#define CHECK_FATAL(exp, ...)                      \
        check_common(FATAL, exp, __VA_ARGS__)      \

#define CHECK_FATAL_RET_VAL(exp, ret_val, ...)                          \
        check_common_ret_val(FATAL, exp, ret_val, __VA_ARGS__)          \

#define CHECK_FATAL_RET(exp, ...)                           \
        check_common_ret(FATAL, exp, __VA_ARGS__)           \

#define CHECK_FATAL_GOTO(exp, label, ...)                           \
        check_common_goto(FATAL, exp, label, __VA_ARGS__)           \

#define CHECK_FATAL_CONTINUE(exp, ...)                              \
        check_common_continue(FATAL, exp, __VA_ARGS__)              \

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 expandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
