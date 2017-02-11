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

#include <ctype.h>

#include "util.h"

char *rstrip(char *a, size_t len, ssize_t *newlen)
{
        char *e = a + len - 1;
        if (len < 1) {
                return a;
        }

        for (;;) {
                if (!isspace(*e) || e <= a) {
                        break;
                }
                --e;
        }
        if (newlen) {
                *newlen = e - a + 1;
        }

        *(e + 1) = '\0';
        return a;
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
