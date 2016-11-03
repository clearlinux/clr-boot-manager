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

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "bootman.h"
#include "bootman_private.h"
#include "log.h"
#include "nica/files.h"

/**
 * In future we'll replace with an INI file for all of CBM config
 */
#define BOOT_TIMEOUT_CONFIG SYSCONFDIR "/boot_timeout.conf"

bool boot_manager_set_timeout_value(BootManager *self, int timeout)
{
        autofree(FILE) *fp = NULL;
        autofree(char) *path = NULL;

        if (!self || !self->sysconfig) {
                return false;
        }

        if (asprintf(&path, "%s%s", self->sysconfig->prefix, BOOT_TIMEOUT_CONFIG) < 0) {
                DECLARE_OOM();
                return -1;
        }

        if (timeout <= 0) {
                /* Nothing to be done here. */
                if (!nc_file_exists(path)) {
                        return true;
                }
                if (unlink(path) < 0) {
                        LOG_ERROR("Unable to remove %s: %s", path, strerror(errno));
                        return false;
                }
                return true;
        }

        fp = fopen(path, "w");
        if (!fp) {
                LOG_FATAL("Unable to open %s for writing: %s", path, strerror(errno));
                return false;
        }

        if (fprintf(fp, "%d\n", timeout) < 0) {
                LOG_FATAL("Unable to set new timeout: %s", strerror(errno));
                return false;
        }
        return true;
}

int boot_manager_get_timeout_value(BootManager *self)
{
        autofree(FILE) *fp = NULL;
        autofree(char) *path = NULL;
        int t_val;

        if (!self || !self->sysconfig) {
                return false;
        }

        if (asprintf(&path, "%s%s", self->sysconfig->prefix, BOOT_TIMEOUT_CONFIG) < 0) {
                DECLARE_OOM();
                return -1;
        }

        /* Default timeout being -1, i.e. don't use one */
        if (!nc_file_exists(path)) {
                return -1;
        }

        fp = fopen(path, "r");
        if (!fp) {
                LOG_FATAL("Unable to open %s for reading: %s", path, strerror(errno));
                return -1;
        }

        if (fscanf(fp, "%d\n", &t_val) != 1) {
                LOG_ERROR("Failed to parse config file, defaulting to no timeout");
                return -1;
        }

        return t_val;
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
