/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2016 Intel Corporation
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
        CBM_LOG_FATAL
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
