/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2017 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

/* This file is a stub implementing happy src/lib/bootvar.h API. */

#include <bootvar.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int bootvar_init(void)
{
        return 0;
}
void bootvar_destroy(void)
{
        return;
}

int bootvar_create(const char *mnt_path, const char *bootloader_path, char *name, size_t sz)
{
        (void)mnt_path;
        (void)bootloader_path;
        static char *stub_name = "Boot0001";
        static size_t len = 8; // strlen(stub_name)
        if (name && sz > len) {
                snprintf(name, len + 1, "%s", stub_name);
        }
        return 0;
}
