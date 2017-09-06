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
#include "system_stub.h"
#include "util.h"
#include "writer.h"

#define CBM_MBR_SYSLINUX_SIZE 440

static KernelArray *kernel_queue = NULL;
static char *extlinux_cmd = NULL;
static char *base_path = NULL;

static bool syslinux_init(const BootManager *manager)
{
        autofree(char) *ldlinux = NULL;
        const char *prefix = NULL;

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

        ldlinux = string_printf("%s/ldlinux.sys", base_path);

        prefix = boot_manager_get_prefix((BootManager *)manager);

        if (nc_file_exists(ldlinux)) {
                extlinux_cmd =
                    string_printf("%s/usr/bin/extlinux -U %s &> /dev/null", prefix, base_path);
        } else {
                extlinux_cmd =
                    string_printf("%s/usr/bin/extlinux -i %s &> /dev/null", prefix, base_path);
        }

        return true;
}

/* Queue kernel to be added to conf */
static bool syslinux_install_kernel(__cbm_unused__ const BootManager *manager, const Kernel *kernel)
{
        /* We may end up adding the same kernel again, when in repair situations
         * for existing kernels (and current == tip cases)
         */
        for (uint16_t i = 0; i < kernel_queue->len; i++) {
                const Kernel *k = nc_array_get(kernel_queue, i);
                if (streq(k->source.path, kernel->source.path)) {
                        return true;
                }
        }

        if (!nc_array_add(kernel_queue, (void *)kernel)) {
                DECLARE_OOM();
                abort();
        }

        return true;
}

/* No op due since conf file will only have queued kernels anyway */
static bool syslinux_remove_kernel(__cbm_unused__ const BootManager *manager,
                                   __cbm_unused__ const Kernel *kernel)
{
        return true;
}

/* Actually creates the whole conf by iterating through the queued kernels */
static bool syslinux_set_default_kernel(const BootManager *manager, const Kernel *default_kernel)
{
        autofree(char) *config_path = NULL;
        const CbmDeviceProbe *root_dev = NULL;
        autofree(char) *old_conf = NULL;
        autofree(CbmWriter) *writer = CBM_WRITER_INIT;

        root_dev = boot_manager_get_root_device((BootManager *)manager);
        if (!root_dev) {
                LOG_FATAL("Root device unknown, this should never happen!");
                return false;
        }

        config_path = string_printf("%s/syslinux.cfg", base_path);

        if (!cbm_writer_open(writer)) {
                DECLARE_OOM();
                abort();
        }

        /* No default kernel for set timeout */
        if (!default_kernel) {
                cbm_writer_append(writer, "TIMEOUT 100\n");
        }

        for (uint16_t i = 0; i < kernel_queue->len; i++) {
                const Kernel *k = nc_array_get(kernel_queue, i);

                /* Mark it default */
                if (default_kernel && streq(k->source.path, default_kernel->source.path)) {
                        cbm_writer_append_printf(writer, "DEFAULT %s\n", k->target.legacy_path);
                }

                cbm_writer_append_printf(writer, "LABEL %s\n", k->target.legacy_path);
                cbm_writer_append_printf(writer, "  KERNEL %s\n", k->target.legacy_path);
                /* Add the initrd if we found one */
                if (k->target.initrd_path) {
                        cbm_writer_append_printf(writer, "  INITRD %s\n", k->target.initrd_path);
                }

                /* Begin options */
                cbm_writer_append(writer, "APPEND ");

                /* Write out root UUID */
                if (root_dev->part_uuid) {
                        cbm_writer_append_printf(writer, "root=PARTUUID=%s ", root_dev->part_uuid);
                } else {
                        cbm_writer_append_printf(writer, "root=UUID=%s ", root_dev->uuid);
                }
                /* Add LUKS information if relevant */
                if (root_dev->luks_uuid) {
                        cbm_writer_append_printf(writer, "rd.luks.uuid=%s ", root_dev->luks_uuid);
                }

                /* Write out the cmdline */
                cbm_writer_append_printf(writer, "%s\n", k->meta.cmdline);
        }

        cbm_writer_close(writer);

        if (cbm_writer_error(writer) != 0) {
                DECLARE_OOM();
                abort();
        }

        /* If the file is the same, don't write it again or sync */
        if (file_get_text(config_path, &old_conf)) {
                if (streq(old_conf, writer->buffer)) {
                        return true;
                }
        }

        if (!file_set_text(config_path, writer->buffer)) {
                LOG_FATAL("syslinux_set_default_kernel: Failed to write %s: %s",
                          config_path,
                          strerror(errno));
                return false;
        }

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

        syslinux_path = string_printf("%s/usr/share/syslinux/gptmbr.bin", prefix);

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

        if (cbm_system_system(extlinux_cmd) != 0) {
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

static int syslinux_get_capabilities(__cbm_unused__ const BootManager *manager)
{
        return BOOTLOADER_CAP_GPT | BOOTLOADER_CAP_LEGACY;
}

__cbm_export__ const BootLoader
    syslinux_bootloader = {.name = "syslinux",
                           .init = syslinux_init,
                           .get_kernel_dst = NULL, /* kernel dir only needed for EFI-enable
                                                      bootloaders */
                           .install_kernel = syslinux_install_kernel,
                           .remove_kernel = syslinux_remove_kernel,
                           .set_default_kernel = syslinux_set_default_kernel,
                           .needs_install = syslinux_needs_install,
                           .needs_update = syslinux_needs_update,
                           .install = syslinux_install,
                           .update = syslinux_update,
                           .remove = syslinux_remove,
                           .destroy = syslinux_destroy,
                           .get_capabilities = syslinux_get_capabilities };

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
