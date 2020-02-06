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
#include "mbr.h"

static KernelArray *kernel_queue = NULL;
static char *extlinux_cmd = NULL;
static char *base_path = NULL;

static bool extlinux_init(const BootManager *manager)
{
        autofree(char) *ldlinux = NULL;
        const char *prefix = NULL;
        autofree(char) *boot_device = NULL;

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
        boot_device = get_legacy_boot_device((char *)prefix);

        if (!boot_device) {
                boot_device = get_boot_device();
        }

        CHECK_ERR_RET_VAL(!boot_device, false, "No boot partition found, you need to "
                          "mark the boot partition with \"legacy_boot\" flag.");

        extlinux_cmd = string_printf("%s/usr/bin/extlinux -i %s --device %s &> /dev/null",
                                     prefix, base_path, boot_device);

        return true;
}

/* Queue kernel to be added to conf */
static bool extlinux_install_kernel(__cbm_unused__ const BootManager *manager, const Kernel *kernel)
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
static bool extlinux_remove_kernel(__cbm_unused__ const BootManager *manager,
                                   __cbm_unused__ const Kernel *kernel)
{
        return true;
}

/* Actually creates the whole conf by iterating through the queued kernels */
static bool extlinux_set_default_kernel(const BootManager *manager, const Kernel *default_kernel)
{
        autofree(char) *config_path = NULL;
        const CbmDeviceProbe *root_dev = NULL;
        autofree(char) *old_conf = NULL;
        autofree(CbmWriter) *writer = CBM_WRITER_INIT;
        NcHashmapIter iter = { 0 };
        char *initrd_name = NULL;

        root_dev = boot_manager_get_root_device((BootManager *)manager);
        if (!root_dev) {
                LOG_FATAL("Root device unknown, this should never happen!");
                return false;
        }

        config_path = string_printf("%s/syslinux.cfg", base_path);
        LOG_DEBUG("Writing extlinux config to: %s", config_path);

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
                autofree(char) *initrd_paths = NULL;
                initrd_paths = malloc(1);
                initrd_paths[0] = '\0';

                /* Mark it default */
                if (default_kernel && streq(k->source.path, default_kernel->source.path)) {
                        cbm_writer_append_printf(writer, "DEFAULT %s\n", k->target.legacy_path);
                }

                cbm_writer_append_printf(writer, "LABEL %s\n", k->target.legacy_path);
                cbm_writer_append_printf(writer, "  KERNEL %s\n", k->target.legacy_path);

                /* Add the initrd if we found one */
                if (k->target.initrd_path) {
                        char *tmp = initrd_paths;
                        initrd_paths = string_printf("%s,%s", initrd_paths, k->target.initrd_path);
                        free(tmp);
                }
                boot_manager_initrd_iterator_init(manager, &iter);
                while (boot_manager_initrd_iterator_next(&iter, &initrd_name)) {
                        char *tmp = initrd_paths;
                        initrd_paths = string_printf("%s,%s", initrd_paths, initrd_name);
                        free(tmp);
                }

                if (strlen(initrd_paths)) {
                        cbm_writer_append_printf(writer, "  INITRD %s\n", initrd_paths + 1);
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
                LOG_FATAL("extlinux_set_default_kernel: Failed to write %s: %s",
                          config_path,
                          strerror(errno));
                return false;
        }

        cbm_sync();
        return true;
}

char *extlinux_get_default_kernel(__cbm_unused__ const BootManager *manager)
{
        return NULL;
}

static bool extlinux_needs_update(__cbm_unused__ const BootManager *manager)
{
        return true;
}

static bool extlinux_needs_install(__cbm_unused__ const BootManager *manager)
{
        return true;
}

static bool extlinux_install(const BootManager *manager)
{
        autofree(char) *boot_device = NULL;
        const char *prefix = NULL;
        int mbr = -1;
        ssize_t count = 0;
        bool is_gpt = false;

        prefix = boot_manager_get_prefix((BootManager *)manager);
        boot_device = get_parent_disk((char *)prefix);
        mbr = open(boot_device, O_WRONLY);
        if (mbr < 0) {
                return false;
        }

        is_gpt = boot_manager_get_wanted_boot_mask((BootManager *)manager)
                        & BOOTLOADER_CAP_GPT;
        count = write(mbr, is_gpt ? syslinux_gptmbr_bin : syslinux_mbr_bin,
                        MBR_BIN_LEN);
        LOG_DEBUG("wrote \"%s.bin\" to %s", is_gpt ? "gptmbr" : "mbr",
                        boot_device);

        CHECK_ERR_GOTO(count != MBR_BIN_LEN, mbr_error,
                       "Written mbr size doesn't match the expected");

        close(mbr);

        CHECK_ERR_RET_VAL(cbm_system_system(extlinux_cmd) != 0, false,
                          "cbm_system_system() returned value != 0");

        cbm_sync();
        return true;

 mbr_error:
        close(mbr);
        return false;
}

static bool extlinux_update(const BootManager *manager)
{
        return extlinux_install(manager);
}

static bool extlinux_remove(__cbm_unused__ const BootManager *manager)
{
        /* Maybe should return false? Unsure */
        return true;
}

static void extlinux_destroy(__cbm_unused__ const BootManager *manager)
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

static int extlinux_get_capabilities(const BootManager *manager)
{
        const char *prefix = NULL;
        autofree(char) *command = NULL;

        prefix = boot_manager_get_prefix((BootManager *)manager);
        command = string_printf("%s/usr/bin/extlinux", prefix);
        if (access(command, X_OK) != 0) {
                LOG_DEBUG("extlinux not found at %s\n", command);
                return 0;
        }

        return BOOTLOADER_CAP_GPT | BOOTLOADER_CAP_LEGACY | BOOTLOADER_CAP_EXTFS;
}

__cbm_export__ const BootLoader extlinux_bootloader = {.name = "extlinux",
                                                       .init = extlinux_init,
                                                       .install_kernel = extlinux_install_kernel,
                                                       .remove_kernel = extlinux_remove_kernel,
                                                       .set_default_kernel =
                                                           extlinux_set_default_kernel,
                                                       .get_default_kernel =
                                                           extlinux_get_default_kernel,
                                                       .needs_install = extlinux_needs_install,
                                                       .needs_update = extlinux_needs_update,
                                                       .install = extlinux_install,
                                                       .update = extlinux_update,
                                                       .remove = extlinux_remove,
                                                       .destroy = extlinux_destroy,
                                                       .get_capabilities =
                                                           extlinux_get_capabilities };

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
