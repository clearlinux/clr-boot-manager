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

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bootloader.h"
#include "bootman.h"
#include "files.h"
#include "log.h"
#include "nica/files.h"
#include "systemd-class.h"
#include "util.h"

/**
 * Private to systemd-class implementation
 */
typedef struct SdClassConfig {
        char *efi_dir;
        char *vendor_dir;
        char *entries_dir;
        char *base_path;
        char *ia32_source;
        char *ia32_dest;
        char *x64_source;
        char *x64_dest;
        char *default_path_ia32;
        char *default_path_x64;
        char *loader_config;
} SdClassConfig;

static SdClassConfig sd_class_config = { 0 };
static BootLoaderConfig *sd_config = NULL;

#define FREE_IF_SET(x)                                                                             \
        {                                                                                          \
                if (x) {                                                                           \
                        free(x);                                                                   \
                        x = NULL;                                                                  \
                }                                                                                  \
        }

static bool sd_class_install_x64(const BootManager *manager);
static bool sd_class_update_x64(const BootManager *manager);

static bool sd_class_install_ia32(const BootManager *manager);
static bool sd_class_update_ia32(const BootManager *manager);

bool sd_class_init(const BootManager *manager, BootLoaderConfig *config)
{
        char *base_path = NULL;
        char *efi_dir = NULL;
        char *vendor_dir = NULL;
        char *entries_dir = NULL;
        char *ia32_source = NULL;
        char *ia32_dest = NULL;
        char *x64_source = NULL;
        char *x64_dest = NULL;
        char *default_path_ia32 = NULL;
        char *default_path_x64 = NULL;
        char *loader_config = NULL;
        const char *prefix = NULL;

        sd_config = config;

        /* Cache all of these to save useless allocs of the same paths later */
        base_path = boot_manager_get_boot_dir((BootManager *)manager);
        OOM_CHECK_RET(base_path, false);
        sd_class_config.base_path = base_path;

        efi_dir = nc_build_case_correct_path(base_path, "EFI", "Boot", NULL);
        OOM_CHECK_RET(efi_dir, false);
        sd_class_config.efi_dir = efi_dir;

        vendor_dir = nc_build_case_correct_path(base_path, "EFI", sd_config->vendor_dir, NULL);
        OOM_CHECK_RET(vendor_dir, false);
        sd_class_config.vendor_dir = vendor_dir;

        entries_dir = nc_build_case_correct_path(base_path, "loader", "entries", NULL);
        OOM_CHECK_RET(entries_dir, false);
        sd_class_config.entries_dir = entries_dir;

        prefix = boot_manager_get_prefix((BootManager *)manager);

        /* ia32 paths */
        if (asprintf(&ia32_source, "%s/%s/%s", prefix, sd_config->efi_dir, sd_config->ia32_blob) <
            0) {
                sd_class_destroy(manager);
                DECLARE_OOM();
                return false;
        }
        sd_class_config.ia32_source = ia32_source;

        ia32_dest = nc_build_case_correct_path(sd_class_config.base_path,
                                               "EFI",
                                               sd_config->vendor_dir,
                                               sd_config->ia32_blob,
                                               NULL);
        OOM_CHECK_RET(ia32_source, false);
        sd_class_config.ia32_dest = ia32_dest;

        /* x64 paths */
        if (asprintf(&x64_source, "%s/%s/%s", prefix, sd_config->efi_dir, sd_config->x64_blob) <
            0) {
                sd_class_destroy(manager);
                DECLARE_OOM();
                return false;
        }
        sd_class_config.x64_source = x64_source;

        x64_dest = nc_build_case_correct_path(sd_class_config.base_path,
                                              "EFI",
                                              sd_config->vendor_dir,
                                              sd_config->x64_blob,
                                              NULL);
        OOM_CHECK_RET(x64_dest, false);
        sd_class_config.x64_dest = x64_dest;

        /* default x64 path */
        default_path_x64 = nc_build_case_correct_path(sd_class_config.base_path,
                                                      "EFI",
                                                      "Boot",
                                                      "BOOTX64.EFI",
                                                      NULL);
        OOM_CHECK_RET(default_path_x64, false);
        sd_class_config.default_path_x64 = default_path_x64;

        /* default ia32 path */
        default_path_ia32 = nc_build_case_correct_path(sd_class_config.base_path,
                                                       "EFI",
                                                       "Boot",
                                                       "BOOTIA32.EFI",
                                                       NULL);
        OOM_CHECK_RET(default_path_ia32, false);
        sd_class_config.default_path_ia32 = default_path_ia32;

        /* Loader entry */
        loader_config =
            nc_build_case_correct_path(sd_class_config.base_path, "loader", "loader.conf", NULL);
        OOM_CHECK_RET(loader_config, false);
        sd_class_config.loader_config = loader_config;

        return true;
}

void sd_class_destroy(__cbm_unused__ const BootManager *manager)
{
        FREE_IF_SET(sd_class_config.efi_dir);
        FREE_IF_SET(sd_class_config.vendor_dir);
        FREE_IF_SET(sd_class_config.entries_dir);
        FREE_IF_SET(sd_class_config.base_path);
        FREE_IF_SET(sd_class_config.ia32_source);
        FREE_IF_SET(sd_class_config.ia32_dest);
        FREE_IF_SET(sd_class_config.x64_source);
        FREE_IF_SET(sd_class_config.x64_dest);
        FREE_IF_SET(sd_class_config.default_path_ia32);
        FREE_IF_SET(sd_class_config.default_path_x64);
        FREE_IF_SET(sd_class_config.loader_config);
}

/* i.e. $prefix/$boot/loader/entries/Clear-linux-native-4.1.6-113.conf */
static char *get_entry_path_for_kernel(BootManager *manager, const Kernel *kernel)
{
        if (!manager || !kernel) {
                return NULL;
        }
        autofree(char) *item_name = NULL;
        const char *prefix = NULL;

        prefix = boot_manager_get_vendor_prefix(manager);

        if (asprintf(&item_name,
                     "%s-%s-%s-%d.conf",
                     prefix,
                     kernel->ktype,
                     kernel->version,
                     kernel->release) < 0) {
                DECLARE_OOM();
                abort();
        }

        return nc_build_case_correct_path(sd_class_config.base_path,
                                          "loader",
                                          "entries",
                                          item_name,
                                          NULL);
}

static bool sd_class_ensure_dirs(__cbm_unused__ const BootManager *manager)
{
        if (!nc_mkdir_p(sd_class_config.efi_dir, 00755)) {
                LOG_FATAL("Failed to create %s: %s", sd_class_config.efi_dir, strerror(errno));
                return false;
        }
        cbm_sync();

        if (!nc_mkdir_p(sd_class_config.vendor_dir, 00755)) {
                LOG_FATAL("Failed to create %s: %s", sd_class_config.vendor_dir, strerror(errno));
                return false;
        }
        cbm_sync();

        if (!nc_mkdir_p(sd_class_config.entries_dir, 00755)) {
                LOG_FATAL("Failed to create %s: %s", sd_class_config.entries_dir, strerror(errno));
                return false;
        }
        cbm_sync();

        return true;
}

bool sd_class_install_kernel(const BootManager *manager, const Kernel *kernel)
{
        if (!manager || !kernel) {
                return false;
        }
        autofree(char) *conf_path = NULL;
        const char *root_uuid = NULL;
        autofree(char) *boot_options = NULL;
        autofree(char) *conf_entry = NULL;
        autofree(char) *kname_copy = NULL;
        const char *os_name = NULL;
        char *kname_base = NULL;
        autofree(char) *old_conf = NULL;

        conf_path = get_entry_path_for_kernel((BootManager *)manager, kernel);

        /* Ensure all the relevant directories exist */
        if (!sd_class_ensure_dirs(manager)) {
                LOG_FATAL("Failed to create required directories");
                return false;
        }

        /* Build the options for the entry */
        root_uuid = boot_manager_get_root_uuid((BootManager *)manager);
        if (!root_uuid) {
                LOG_FATAL("PartUUID unknown, this should never happen! %s", kernel->path);
                return false;
        } else {
                if (asprintf(&boot_options,
                             "options root=PARTUUID=%s %s",
                             root_uuid,
                             kernel->cmdline) < 0) {
                        DECLARE_OOM();
                        abort();
                }
        }

        kname_copy = strdup(kernel->path);
        kname_base = basename(kname_copy);

        os_name = boot_manager_get_os_name((BootManager *)manager);

        /* Kernels are installed to the root of the ESP, namespaced */
        if (asprintf(&conf_entry, "title %s\nlinux /%s\n%s\n", os_name, kname_base, boot_options) <
            0) {
                DECLARE_OOM();
                abort();
        }

        /* If our new config matches the old config, just return. */
        if (file_get_text(conf_path, &old_conf)) {
                if (streq(old_conf, conf_entry)) {
                        return true;
                }
        }

        if (!file_set_text(conf_path, conf_entry)) {
                LOG_FATAL("Failed to create loader entry for: %s [%s]",
                          kernel->path,
                          strerror(errno));
                return false;
        }

        cbm_sync();

        return true;
}

bool sd_class_remove_kernel(const BootManager *manager, const Kernel *kernel)
{
        if (!manager || !kernel) {
                return false;
        }

        autofree(char) *conf_path = NULL;
        autofree(char) *kname_copy = NULL;
        autofree(char) *kfile_target = NULL;

        conf_path = get_entry_path_for_kernel((BootManager *)manager, kernel);
        OOM_CHECK_RET(conf_path, false);

        /* We must take a non-fatal approach in a remove operation */
        if (nc_file_exists(conf_path)) {
                if (unlink(conf_path) < 0) {
                        LOG_ERROR("sd_class_remove_kernel: Failed to remove %s: %s",
                                  conf_path,
                                  strerror(errno));
                } else {
                        cbm_sync();
                }
        }

        return true;
}

bool sd_class_set_default_kernel(const BootManager *manager, const Kernel *kernel)
{
        if (!manager) {
                return false;
        }

        if (!sd_class_ensure_dirs(manager)) {
                LOG_FATAL("Failed to create required directories for %s", sd_config->name);
                return false;
        }

        autofree(char) *item_name = NULL;
        int timeout = 0;
        const char *prefix = NULL;
        autofree(char) *old_conf = NULL;

        prefix = boot_manager_get_vendor_prefix((BootManager *)manager);

        /* No default possible, set high time out */
        if (!kernel) {
                item_name = strdup("timeout 10\n");
                if (!item_name) {
                        DECLARE_OOM();
                        return false;
                }
                /* Check if the config changed and write the new one */
                goto write_config;
        }

        timeout = boot_manager_get_timeout_value((BootManager *)manager);

        if (timeout > 0) {
                /* Set the timeout as configured by the user */
                if (asprintf(&item_name,
                             "timeout %d\ndefault %s-%s-%s-%d\n",
                             timeout,
                             prefix,
                             kernel->ktype,
                             kernel->version,
                             kernel->release) < 0) {
                        DECLARE_OOM();
                        return false;
                }
        } else {
                if (asprintf(&item_name,
                             "default %s-%s-%s-%d\n",
                             prefix,
                             kernel->ktype,
                             kernel->version,
                             kernel->release) < 0) {
                        DECLARE_OOM();
                        return false;
                }
        }

write_config:
        if (file_get_text(sd_class_config.loader_config, &old_conf)) {
                if (streq(old_conf, item_name)) {
                        return true;
                }
        }

        if (!file_set_text(sd_class_config.loader_config, item_name)) {
                LOG_FATAL("sd_class_set_default_kernel: Failed to write %s: %s",
                          sd_class_config.loader_config,
                          strerror(errno));
                return false;
        }

        cbm_sync();

        return true;
}

bool sd_class_needs_install(const BootManager *manager)
{
        if (!manager) {
                return false;
        }

        const char *paths[2] = { 0 };
        const char *source_path = NULL;

        if (boot_manager_get_architecture_size((BootManager *)manager) == 64) {
                if (boot_manager_get_platform_size((BootManager *)manager) != 64) {
                        paths[0] = sd_class_config.ia32_dest;
                        paths[1] = sd_class_config.default_path_ia32;
                        source_path = sd_class_config.ia32_source;
                } else {
                        paths[0] = sd_class_config.x64_dest;
                        paths[1] = sd_class_config.default_path_x64;
                        source_path = sd_class_config.x64_source;
                }
        } else {
                paths[0] = sd_class_config.ia32_dest;
                paths[1] = sd_class_config.default_path_ia32;
                source_path = sd_class_config.ia32_source;
        }

        /* Catch this in the install */
        if (!nc_file_exists(source_path)) {
                return true;
        }

        /* Try to see if targets are missing */
        for (size_t i = 0; i < ARRAY_SIZE(paths); i++) {
                const char *check_p = paths[i];

                if (!nc_file_exists(check_p)) {
                        return true;
                }
        }

        return false;
}

bool sd_class_needs_update(const BootManager *manager)
{
        if (!manager) {
                return false;
        }

        const char *paths[2] = { 0 };
        const char *source_path = NULL;

        if (boot_manager_get_architecture_size((BootManager *)manager) == 64) {
                if (boot_manager_get_platform_size((BootManager *)manager) != 64) {
                        paths[0] = sd_class_config.ia32_dest;
                        paths[1] = sd_class_config.default_path_ia32;
                        source_path = sd_class_config.ia32_source;
                } else {
                        paths[0] = sd_class_config.x64_dest;
                        paths[1] = sd_class_config.default_path_x64;
                        source_path = sd_class_config.x64_source;
                }
        } else {
                paths[0] = sd_class_config.ia32_dest;
                paths[1] = sd_class_config.default_path_ia32;
                source_path = sd_class_config.ia32_source;
        }

        for (size_t i = 0; i < ARRAY_SIZE(paths); i++) {
                const char *check_p = paths[i];

                if (nc_file_exists(check_p) && !cbm_files_match(source_path, check_p)) {
                        return true;
                }
        }

        return false;
}

/**
 * Install the 64-bit specific components
 */
static bool sd_class_install_x64(const BootManager *manager)
{
        if (!manager) {
                return false;
        }

        /* Install vendor x64 blob */
        if (!copy_file_atomic(sd_class_config.x64_source, sd_class_config.x64_dest, 00644)) {
                LOG_FATAL("Failed to install %s: %s", sd_class_config.x64_dest, strerror(errno));
                return false;
        }
        cbm_sync();

        /* Install default x64 blob */
        if (!copy_file_atomic(sd_class_config.x64_source,
                              sd_class_config.default_path_x64,
                              00644)) {
                LOG_FATAL("Failed to install %s: %s",
                          sd_class_config.default_path_x64,
                          strerror(errno));
                return false;
        }
        cbm_sync();

        return true;
}

static bool sd_class_install_ia32(const BootManager *manager)
{
        if (!manager) {
                return false;
        }

        /* Install vendor ia32 blob */
        if (!copy_file_atomic(sd_class_config.ia32_source, sd_class_config.ia32_dest, 00644)) {
                LOG_FATAL("Failed to install %s: %s", sd_class_config.ia32_dest, strerror(errno));
                return false;
        }
        cbm_sync();

        /* Install default ia32 blob */
        if (!copy_file_atomic(sd_class_config.ia32_source,
                              sd_class_config.default_path_ia32,
                              00644)) {
                LOG_FATAL("Failed to install %s: %s",
                          sd_class_config.default_path_ia32,
                          strerror(errno));
                return false;
        }
        cbm_sync();

        return true;
}

bool sd_class_install(const BootManager *manager)
{
        if (!manager) {
                return false;
        }

        if (!sd_class_ensure_dirs(manager)) {
                LOG_FATAL("Failed to create required directories for %s", sd_config->name);
                return false;
        }

        if (boot_manager_get_architecture_size((BootManager *)manager) == 32) {
                if (boot_manager_get_platform_size((BootManager *)manager) == 64 &&
                    nc_file_exists(sd_class_config.x64_source)) {
                        /* 32-bit OS that has access to 64-bit sdclass bootloader, use this */
                        return sd_class_install_x64(manager);
                } else {
                        /* Either 32-bit UEFI or no 64-bit loader available */
                        return sd_class_install_ia32(manager);
                }
        } else {
                if (boot_manager_get_platform_size((BootManager *)manager) == 32) {
                        /* 64-bit OS on 32-bit UEFI */
                        return sd_class_install_ia32(manager);
                } else {
                        return sd_class_install_x64(manager);
                }
        }
}

static bool sd_class_update_ia32(const BootManager *manager)
{
        if (!manager) {
                return false;
        }

        if (!cbm_files_match(sd_class_config.ia32_source, sd_class_config.ia32_dest)) {
                if (!copy_file_atomic(sd_class_config.ia32_source,
                                      sd_class_config.ia32_dest,
                                      00644)) {
                        LOG_FATAL("Failed to update %s: %s",
                                  sd_class_config.ia32_dest,
                                  strerror(errno));
                        return false;
                }
        }
        cbm_sync();

        if (!cbm_files_match(sd_class_config.ia32_source, sd_class_config.default_path_ia32)) {
                if (!copy_file_atomic(sd_class_config.ia32_source,
                                      sd_class_config.default_path_ia32,
                                      00644)) {
                        LOG_FATAL("Failed to update %s: %s",
                                  sd_class_config.default_path_ia32,
                                  strerror(errno));
                        return false;
                }
        }
        cbm_sync();

        return true;
}

static bool sd_class_update_x64(const BootManager *manager)
{
        if (!manager) {
                return false;
        }

        if (!cbm_files_match(sd_class_config.x64_source, sd_class_config.x64_dest)) {
                if (!copy_file_atomic(sd_class_config.x64_source,
                                      sd_class_config.x64_dest,
                                      00644)) {
                        LOG_FATAL("Failed to update %s: %s",
                                  sd_class_config.x64_dest,
                                  strerror(errno));
                        return false;
                }
        }
        cbm_sync();

        if (!cbm_files_match(sd_class_config.x64_source, sd_class_config.default_path_x64)) {
                if (!copy_file_atomic(sd_class_config.x64_source,
                                      sd_class_config.default_path_x64,
                                      00644)) {
                        LOG_FATAL("Failed to update %s: %s",
                                  sd_class_config.default_path_x64,
                                  strerror(errno));
                        return false;
                }
        }
        cbm_sync();

        return true;
}

bool sd_class_update(const BootManager *manager)
{
        if (!manager) {
                return false;
        }
        if (!sd_class_ensure_dirs(manager)) {
                LOG_FATAL("Failed to create required directories for %s", sd_config->name);
                return false;
        }

        if (boot_manager_get_architecture_size((BootManager *)manager) == 32) {
                if (boot_manager_get_platform_size((BootManager *)manager) == 64 &&
                    nc_file_exists(sd_class_config.x64_source)) {
                        /* 32-bit OS that has access to 64-bit sdclass bootloader, use this */
                        return sd_class_update_x64(manager);
                } else {
                        /* Either 32-bit UEFI or no 64-bit loader available */
                        return sd_class_update_ia32(manager);
                }
        } else {
                if (boot_manager_get_platform_size((BootManager *)manager) == 32) {
                        /* 64-bit OS on 32-bit UEFI */
                        return sd_class_update_ia32(manager);
                } else {
                        return sd_class_update_x64(manager);
                }
        }
}

bool sd_class_remove(const BootManager *manager)
{
        if (!manager) {
                return false;
        }

        /* We call multiple syncs in case something goes wrong in removal, where we could be seeing
         * an ESP umount after */
        if (nc_file_exists(sd_class_config.vendor_dir) && !nc_rm_rf(sd_class_config.vendor_dir)) {
                LOG_FATAL("Failed to remove vendor dir: %s", strerror(errno));
                return false;
        }
        cbm_sync();

        if (nc_file_exists(sd_class_config.default_path_ia32) &&
            unlink(sd_class_config.default_path_ia32) < 0) {
                LOG_FATAL("Failed to remove %s: %s",
                          sd_class_config.default_path_ia32,
                          strerror(errno));
                return false;
        }
        cbm_sync();

        if (nc_file_exists(sd_class_config.default_path_x64) &&
            unlink(sd_class_config.default_path_x64) < 0) {
                LOG_FATAL("Failed to remove %s: %s",
                          sd_class_config.default_path_x64,
                          strerror(errno));
                return false;
        }
        cbm_sync();

        if (nc_file_exists(sd_class_config.loader_config) &&
            unlink(sd_class_config.loader_config) < 0) {
                LOG_FATAL("Failed to remove %s: %s",
                          sd_class_config.loader_config,
                          strerror(errno));
                return false;
        }
        cbm_sync();

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
