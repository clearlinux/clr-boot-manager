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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <blkid/blkid.h>

#include "bootman.h"
#include "bootman_private.h"
#include "files.h"
#include "log.h"
#include "nica/files.h"
#include "system_stub.h"

#define CBM_BOOTVAR_TEST_MODE_VAR "CBM_BOOTVAR_TEST_MODE"

void cbm_free_sysconfig(SystemConfig *config)
{
        if (!config) {
                return;
        }
        free(config->prefix);
        free(config->boot_device);
        cbm_probe_free(config->root_device);
        free(config);
}

int cbm_get_fstype(const char *boot_device)
{
        int rc;
        blkid_probe pr;
        const char *data;
        int ret = 0;

        /* Test suite will set the CBM_TEST_FSTYPE env var and inform the wanted fstype */
        char *test_mode_fs_type_env = getenv("CBM_TEST_FSTYPE");
        if (test_mode_fs_type_env && !strncmp(test_mode_fs_type_env, "EXTFS", 5)) {
                return BOOTLOADER_CAP_EXTFS;
        } else if (test_mode_fs_type_env && !strncmp(test_mode_fs_type_env, "FATFS", 5)) {
                return BOOTLOADER_CAP_FATFS;
        }

        pr = blkid_new_probe_from_filename(boot_device);
        if (!pr) {
                LOG_ERROR("%s: failed to create a new libblkid probe",
                                boot_device);
                exit(EXIT_FAILURE);
        }

        blkid_probe_set_superblocks_flags(pr, BLKID_SUBLKS_TYPE);
        rc = blkid_do_safeprobe(pr);
        if (rc != 0) {
                LOG_ERROR("%s: blkid_do_safeprobe() failed", boot_device);
                exit(EXIT_FAILURE);
        }

        rc = blkid_probe_lookup_value(pr, "TYPE", &data, NULL);
        if (rc != 0) {
                LOG_ERROR("%s: blkid_probe_lookup_value() failed", boot_device);
                exit(EXIT_FAILURE);
        }

        if ((strcmp(data, "ext2") == 0) ||
            (strcmp(data, "ext3") == 0) ||
            (strcmp(data, "ext4") == 0))
                ret = BOOTLOADER_CAP_EXTFS;
        else if (strcmp(data, "vfat") == 0)
                ret = BOOTLOADER_CAP_FATFS;

        blkid_free_probe(pr);

        return ret;
}

static void cmb_inspect_root_native(SystemConfig *c, char *realp) {
        bool native_uefi = false;
        autofree(char) *fw_path;
        char *boot = NULL;

        /* typically /sys, but we forcibly fail this with our tests */
        fw_path = string_printf("%s/firmware/efi", cbm_system_get_sysfs_path());
        native_uefi = nc_file_exists(fw_path);

        /*
         * Try to find the system ESP. The "force legacy" flag is useful
         * for development purpose only, this is a way to manually test
         * legacy install when we don't a fully prepared environment to that
         * namely: having an installer image capable of booting _and_ installing
         * a legacy bios system.
         */
        if (native_uefi && !getenv("CBM_FORCE_LEGACY")) {
                boot = get_boot_device();
                c->wanted_boot_mask |= BOOTLOADER_CAP_UEFI;

                if (boot) {
                        c->boot_device = boot;
                        c->wanted_boot_mask |= BOOTLOADER_CAP_GPT;
                        LOG_INFO("Discovered UEFI ESP: %s", boot);
                }
        } else {
                /* Find legacy relative to root, on GPT */
                boot = get_legacy_boot_device(realp);
                c->wanted_boot_mask |= BOOTLOADER_CAP_LEGACY;

                if (boot) {
                        c->boot_device = boot;
                        c->wanted_boot_mask |= BOOTLOADER_CAP_GPT;
                        LOG_INFO("Discovered legacy boot device: %s", boot);
                }
        }
}

static void cmb_inspect_root_image(SystemConfig *c, char *realp) {
        char *legacy_boot = NULL;
        char *uefi_boot = NULL;
        char *boot = NULL;
        char *force_legacy = NULL;
        int mask = 0;

        legacy_boot = get_legacy_boot_device(realp);
        uefi_boot = get_boot_device();
        force_legacy = getenv("CBM_FORCE_LEGACY");

        /*
         * uefi has precedence over legacy, if we detected both uefi wins
         * but if force_legacy is set then we honor "users choice"
         */
        if (!force_legacy && ((legacy_boot && uefi_boot) || uefi_boot)) {
                mask = BOOTLOADER_CAP_UEFI | BOOTLOADER_CAP_GPT;
                boot = uefi_boot;
        } else if (legacy_boot || force_legacy) {
                mask = BOOTLOADER_CAP_LEGACY | BOOTLOADER_CAP_GPT;
                boot = legacy_boot;
        }

        c->boot_device = boot;
        c->wanted_boot_mask = mask;
}

SystemConfig *cbm_inspect_root(const char *path, bool image_mode)
{
        SystemConfig *c = NULL;
        char *realp = NULL;
        char *rel = NULL;

        if (!path) {
                return NULL;
        }

        realp = realpath(path, NULL);
        if (!realp) {
                LOG_ERROR("Path specified does not exist: %s", path);
                return NULL;
        }

        c = calloc(1, sizeof(struct SystemConfig));
        if (!c) {
                DECLARE_OOM();
                free(realp);
                return NULL;
        }
        c->prefix = realp;
        c->wanted_boot_mask = 0;

        if (image_mode) {
                cmb_inspect_root_image(c, realp);
        } else {
                cmb_inspect_root_native(c, realp);
        }

        /* Our probe methods are GPT only. If we found one, it's definitely GPT */
        if (c->boot_device) {
                rel = realpath(c->boot_device, NULL);
                if (!rel) {
                        LOG_FATAL("Cannot determine boot device: %s %s",
                                  c->boot_device,
                                  strerror(errno));
                } else {
                        free(c->boot_device);
                        c->boot_device = rel;
                        LOG_INFO("Fully resolved boot device: %s", rel);
                }
                c->wanted_boot_mask |= BOOTLOADER_CAP_GPT;

                /* determine fstype of the boot_device */
                c->wanted_boot_mask |= cbm_get_fstype(c->boot_device);
        }

        c->root_device = cbm_probe_path(realp);

        return c;
}

bool cbm_is_sysconfig_sane(SystemConfig *config)
{
        if (!config) {
                LOG_FATAL("sysconfig insane: Missing config");
                return false;
        }
        if (!config->root_device) {
                LOG_FATAL("sysconfig insane: Missing root device");
                return false;
        }
        return true;
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
