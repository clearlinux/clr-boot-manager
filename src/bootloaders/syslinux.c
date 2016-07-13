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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bootloader.h"
#include "files.h"
#include "log.h"
#include "nica/files.h"
#include "util.h"

#define CBM_MBR_SYSLINUX_SIZE 440

static KernelArray *kernel_queue = NULL;
static char *extlinux_cmd = NULL;
static char *base_path = NULL;

static bool syslinux_init(const BootManager *manager)
{
        autofree(char) *ldlinux = NULL;
        int ret = 0;

        if (kernel_queue) {
                kernel_array_free(kernel_queue);
        }
        kernel_queue = nc_array_new();
        if (!kernel_queue) {
                DECLARE_OOM();
                abort();
        }
        if (base_path) {
                free(base_path);
                base_path = NULL;
        }
        base_path = boot_manager_get_boot_dir((BootManager *)manager);
        OOM_CHECK_RET(base_path, false);

        if (extlinux_cmd) {
                free(extlinux_cmd);
                extlinux_cmd = NULL;
        }
        if (asprintf(&ldlinux, "%s/ldlinux.sys", base_path) < 0) {
                DECLARE_OOM();
                abort();
        }
        if (nc_file_exists(ldlinux)) {
                ret = asprintf(&extlinux_cmd, "extlinux -U %s &> /dev/null", base_path);
        } else {
                ret = asprintf(&extlinux_cmd, "extlinux -i %s &> /dev/null", base_path);
        }
        if (ret < 0) {
                DECLARE_OOM();
                abort();
        }

        return true;
}

/* Queue kernel to be added to conf */
static bool syslinux_install_kernel(__cbm_unused__ const BootManager *manager, const Kernel *kernel)
{
        if (!nc_array_add(kernel_queue, (void *)kernel)) {
                DECLARE_OOM();
                abort();
        }

        return true;
}

/* hack to get all kernels that should be installed in the conf */
static bool syslinux_is_kernel_installed(__cbm_unused__ const BootManager *manager,
                                         __cbm_unused__ const Kernel *kernel)
{
        return false;
}

/* No op due since conf file will only have queued kernels anyway */
static bool syslinux_remove_kernel(__cbm_unused__ const BootManager *manager,
                                   __cbm_unused__ const Kernel *kernel)
{
        return true;
}

/* Actually creates the whole conf by iterating through the queued kernels */
static bool syslinux_set_default_kernel(const BootManager *manager, const Kernel *kernel)
{
        autofree(char) *config_path = NULL;
        const char *root_uuid = NULL;
        char *config_text = NULL;
        char *_config_text = NULL;

        root_uuid = boot_manager_get_root_uuid((BootManager *)manager);
        if (!root_uuid) {
                LOG_FATAL("PartUUID unknown, this should never happen! %s", kernel->path);
                return false;
        }

        if (asprintf(&config_path, "%s/syslinux.cfg", base_path) < 0) {
                DECLARE_OOM();
                abort();
        }

        /* no default set timeout or initialize config_text for looping */
        if (!kernel) {
                if (asprintf(&config_text, "TIMEOUT 100\n") < 0) {
                        DECLARE_OOM();
                        abort();
                }
        } else {
                if (asprintf(&config_text, "\n") < 0) {
                        DECLARE_OOM();
                        abort();
                }
        }

        for (uint16_t i = 0; i < kernel_queue->len; i++) {
                const Kernel *k = nc_array_get(kernel_queue, i);
                char *boot_options = NULL;
                char *kname_base = NULL;
                char *kname_copy = NULL;
                char *default_text = NULL;

                _config_text = config_text;
                config_text = NULL;
                kname_copy = strdup(k->path);
                if (!kname_copy) {
                        DECLARE_OOM();
                        abort();
                }
                kname_base = basename(kname_copy);

                /* Build the options for the entry */
                if (!root_uuid) {
                        if (asprintf(&boot_options, "%s", k->cmdline) < 0) {
                                DECLARE_OOM();
                                abort();
                        }
                } else {
                        if (asprintf(&boot_options, "root=PARTUUID=%s %s", root_uuid, k->cmdline) <
                            0) {
                                DECLARE_OOM();
                                abort();
                        }
                }
                if (streq(k->path, kernel->path)) {
                        if (asprintf(&default_text, "DEFAULT %s\n", kname_base) < 0) {
                                DECLARE_OOM();
                                abort();
                        }
                } else {
                        default_text = "";
                }

                if (asprintf(&config_text,
                             "%s%sLABEL %s\n  KERNEL %s\n  APPEND %s\n",
                             _config_text,
                             default_text,
                             kname_base,
                             kname_base,
                             boot_options) < 0) {
                        DECLARE_OOM();
                        abort();
                }

                free(kname_copy);
                kname_copy = NULL;
                free(boot_options);
                boot_options = NULL;
                if (streq(k->path, kernel->path)) {
                        free(default_text);
                }
                default_text = NULL;
                free(_config_text);
                _config_text = NULL;
        }

        if (!file_set_text(config_path, config_text)) {
                LOG_FATAL("syslinux_set_default_kernel: Failed to write %s: %s",
                          config_path,
                          strerror(errno));
                return false;
        }

        free(config_text);
        config_text = NULL;
        cbm_sync();

        return true;
}

static bool syslinux_needs_update(__cbm_unused__ const BootManager *manager)
{
        return true;
}

static bool syslinux_needs_install(__cbm_unused__ const BootManager *manager)
{
        return true;
}

static bool syslinux_install(const BootManager *manager)
{
        autofree(char) *boot_device = NULL;
        autofree(char) *syslinux_path = NULL;
        const char *prefix = NULL;
        int mbr = -1;
        int syslinux_mbr = -1;
        ssize_t count = 0;

        prefix = boot_manager_get_prefix((BootManager *)manager);
        boot_device = get_parent_disk((char *)prefix);
        mbr = open(boot_device, O_WRONLY);
        if (mbr < 0) {
                return false;
        }

        if (asprintf(&syslinux_path, "%s/usr/share/syslinux/gptmbr.bin", prefix) < 0) {
                DECLARE_OOM();
                abort();
        }
        syslinux_mbr = open(syslinux_path, O_RDONLY);
        if (syslinux_mbr < 0) {
                close(mbr);
                return false;
        }

        count = sendfile(mbr, syslinux_mbr, NULL, CBM_MBR_SYSLINUX_SIZE);
        if (count != CBM_MBR_SYSLINUX_SIZE) {
                close(mbr);
                close(syslinux_mbr);
                return false;
        }
        close(mbr);
        close(syslinux_mbr);

        if (system(extlinux_cmd) != 0) {
                return false;
        }

        cbm_sync();
        return true;
}

static bool syslinux_update(const BootManager *manager)
{
        return syslinux_install(manager);
}

static bool syslinux_remove(__cbm_unused__ const BootManager *manager)
{
        /* Maybe should return false? Unsure */
        return true;
}

static void syslinux_destroy(__cbm_unused__ const BootManager *manager)
{
        if (kernel_queue) {
                /* kernels pointers inside are not owned by the array */
                nc_array_free(&kernel_queue, NULL);
        }
        if (extlinux_cmd) {
                free(extlinux_cmd);
                extlinux_cmd = NULL;
        }
        if (base_path) {
                free(base_path);
                base_path = NULL;
        }
}

__cbm_export__ const BootLoader syslinux_bootloader = {.name = "syslinux",
                                                       .init = syslinux_init,
                                                       .install_kernel = syslinux_install_kernel,
                                                       .is_kernel_installed =
                                                           syslinux_is_kernel_installed,
                                                       .remove_kernel = syslinux_remove_kernel,
                                                       .set_default_kernel =
                                                           syslinux_set_default_kernel,
                                                       .needs_install = syslinux_needs_install,
                                                       .needs_update = syslinux_needs_update,
                                                       .install = syslinux_install,
                                                       .update = syslinux_update,
                                                       .remove = syslinux_remove,
                                                       .destroy = syslinux_destroy };

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
