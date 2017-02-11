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

#pragma once

#define _GNU_SOURCE

#include "nica/util.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define DECLARE_OOM() (fputs("Out of memory", stderr))

#define OOM_CHECK(x)                                                                               \
        {                                                                                          \
                if (!x) {                                                                          \
                        DECLARE_OOM();                                                             \
                        abort();                                                                   \
                }                                                                                  \
        }
#define OOM_CHECK_RET(x, y)                                                                        \
        {                                                                                          \
                if (!x) {                                                                          \
                        DECLARE_OOM();                                                             \
                        return y;                                                                  \
                }                                                                                  \
        }

/** Helper for array looping */
#define ARRAY_SIZE(x) sizeof(x) / sizeof(x[0])

/**
 * Always inline the function
 */
#define __cbm_inline__ __attribute__((always_inline))

/**
 * For quicker development
 */
#define __cbm_unused__ __attribute__((unused))

/**
 * Strip the right side of a string of it's whitespace
 * This must be allocated memory
 */
char *rstrip(char *a, size_t len, ssize_t *newlen);

/**
 * Similar to asprintf, but will assert allocation of the string.
 * Failure to do so will result in an abort, as there is nothing
 * further than clr-boot-manager can do when it has run out of
 * memory.
 */
char *string_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

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
