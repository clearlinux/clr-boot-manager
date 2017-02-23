/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2016-2017 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "nica/util.h"

static FILE *log_file = NULL;
static CbmLogLevel min_log_level;

#define PACKAGE_NAME_SHORT "cbm"

static const char *log_str_table[] = {[CBM_LOG_DEBUG] = "DEBUG",     [CBM_LOG_INFO] = "INFO",
                                      [CBM_LOG_SUCCESS] = "SUCCESS", [CBM_LOG_ERROR] = "ERROR",
                                      [CBM_LOG_WARNING] = "WARNING", [CBM_LOG_FATAL] = "FATAL" };

void cbm_log_init(FILE *log)
{
        const char *env_level = NULL;
        log_file = log;
        unsigned int nlog_level = CBM_LOG_ERROR;

        env_level = getenv("CBM_DEBUG");
        if (env_level) {
                /* =1 becomes 0 */
                nlog_level = ((unsigned int)atoi(env_level)) - 1;
        }
        if (nlog_level >= CBM_LOG_MAX) {
                nlog_level = CBM_LOG_FATAL;
        }
        min_log_level = nlog_level;
}

/**
 * Ensure we're always at least initialised with stderr
 */
__attribute__((constructor)) static void cbm_log_first_init(void)
{
        cbm_log_init(stderr);
}

static inline const char *cbm_log_level_str(CbmLogLevel l)
{
        if (l <= CBM_LOG_FATAL) {
                return log_str_table[l];
        }
        return "unknown";
}

void cbm_log(CbmLogLevel level, const char *filename, int lineno, const char *format, ...)
{
        const char *displ = NULL;
        va_list vargs;
        autofree(char) *rend = NULL;

        /* Respect minimum log level */
        if (level < min_log_level) {
                return;
        }

        displ = cbm_log_level_str(level);

        va_start(vargs, format);

        if (vasprintf(&rend, format, vargs) < 0) {
                fputs("[FATAL] " PACKAGE_NAME_SHORT ": Cannot log to stream", log_file);
                goto clean_args;
        }

        if (fprintf(log_file,
                    "[%s] %s (%s:L%d): %s\n",
                    displ,
                    PACKAGE_NAME_SHORT,
                    filename,
                    lineno,
                    rend) < 0) {
                /* Forcibly fall back to stderr with the error */
                fputs("[FATAL] " PACKAGE_NAME_SHORT ": Cannot log to stream", stderr);
                goto clean_args;
        }

clean_args:
        va_end(vargs);
}

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
