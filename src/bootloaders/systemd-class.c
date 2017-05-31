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
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bootloader.h"
#include "bootman.h"
#include "config.h"
#include "files.h"
#include "log.h"
#include "nica/files.h"
#include "systemd-class.h"
#include "util.h"
#include "writer.h"

/**
 * Private to systemd-class implementation
 */
typedef struct SdClassConfig {
        char *efi_dir;
        char *vendor_dir;
        char *entries_dir;
        char *base_path;
        char *efi_blob_source;
        char *loader_config;
        NcHashmap *copy_pairs; /**< Store key/value (source->dest) mappings for copyig */
        bool secure_boot;
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

/**
 * Insert a copy mapping into the copy_pairs map
 *
 * This function takes nc_build_case_correct_path style arguments to allow
 * wrapping the duplication up in one place.
 * Additionally it will take care of whether the source exists, and build the
 * full source/target paths up in memory.
 *
 * This function will only fail on memory failure, not if the source doesn't
 * exist.
 */
bool sd_class_config_put_copy(const char *prefix, const char *source, ...)
{
        va_list va;

        /* Empty prefix means just use as is */
        char *source_path = NULL;
        if (prefix) {
                source_path = string_printf("%s/%s", prefix, source);
        } else {
                source_path = strdup(source);
        }

        if (!nc_file_exists(source_path)) {
                free(source_path);
                return true;
        }
        va_start(va, source);
        char *dest_path = nc_build_case_correct_path_va(sd_class_config.base_path, va);
        va_end(va);
        if (!dest_path) {
                free(source_path);
                return false;
        }
        /* Store them swapped as target is unique, source might not be */
        return nc_hashmap_put(sd_class_config.copy_pairs, dest_path, source_path);
}

bool sd_class_init(const BootManager *manager, BootLoaderConfig *config)
{
        char *base_path = NULL;
        char *efi_dir = NULL;
        char *vendor_dir = NULL;
        char *entries_dir = NULL;
        char *efi_blob_source = NULL;
        char *loader_config = NULL;
        const char *prefix = NULL;
        NcHashmap *copy_pairs = NULL;
        autofree(char) *shim_path = NULL;
        bool did_put = false;

        sd_config = config;

        /* Init copy pairs table */
        copy_pairs = nc_hashmap_new_full(nc_string_hash, nc_string_compare, free, free);
        if (!copy_pairs) {
                DECLARE_OOM();
                return false;
        }
        sd_class_config.copy_pairs = copy_pairs;

        /* Cache all of these to save useless allocs of the same paths later */
        base_path = boot_manager_get_boot_dir((BootManager *)manager);
        OOM_CHECK_RET(base_path, false);
        sd_class_config.base_path = base_path;

        /* EFI Boot directory base */
        efi_dir = nc_build_case_correct_path(base_path, "EFI", "Boot", NULL);
        OOM_CHECK_RET(efi_dir, false);
        sd_class_config.efi_dir = efi_dir;

        /* Our vendor directory base */
        vendor_dir = nc_build_case_correct_path(base_path, "EFI", sd_config->vendor_dir, NULL);
        OOM_CHECK_RET(vendor_dir, false);
        sd_class_config.vendor_dir = vendor_dir;

        /* loader/entries */
        entries_dir = nc_build_case_correct_path(base_path, "loader", "entries", NULL);
        OOM_CHECK_RET(entries_dir, false);
        sd_class_config.entries_dir = entries_dir;

        prefix = boot_manager_get_prefix((BootManager *)manager);

        /* Determine if we have secure-boot support */
        shim_path = string_printf("%s/usr/share/shim/shim.efi", prefix);
        sd_class_config.secure_boot = nc_file_exists(shim_path);

        /* Our main "blob" */
        efi_blob_source =
            string_printf("%s/%s/%s", prefix, sd_config->efi_dir, sd_config->efi_blob);
        sd_class_config.efi_blob_source = efi_blob_source;

        /* Main vendor blob - always installed */
        did_put = sd_class_config_put_copy(NULL,
                                           efi_blob_source,
                                           "EFI",
                                           sd_config->vendor_dir,
                                           sd_config->efi_blob,
                                           NULL);

        /* Install secure-boot as primary, ourselves as stage2 */
        if (sd_class_config.secure_boot) {
                /* TODO: Add *another* blob to be used by EFI variables by path, not just default */
                did_put = sd_class_config_put_copy(prefix,
                                                   "/usr/share/shim/shim.efi",
                                                   "EFI",
                                                   "Boot",
                                                   DEFAULT_EFI_BLOB,
                                                   NULL);
                did_put = sd_class_config_put_copy(prefix,
                                                   "/usr/share/shim/MokManager.efi",
                                                   "EFI",
                                                   "Boot",
                                                   "MokManager.efi",
                                                   NULL);
                did_put = sd_class_config_put_copy(prefix,
                                                   "/usr/share/shim/fallback.efi",
                                                   "EFI",
                                                   "Boot",
                                                   "fallback.efi",
                                                   NULL);
                /* Install ourselves, additionally, as a stage2 */
                did_put = sd_class_config_put_copy(NULL,
                                                   efi_blob_source,
                                                   "EFI",
                                                   "Boot",
                                                   /* i.e. loaderx64.efi */
                                                   SHIM_STAGE2_PREFIX SYSTEMD_EFI_SUFFIX,
                                                   NULL);
        } else {
                /* No stage2, we take on default BOOTX64.EFI */
                did_put = sd_class_config_put_copy(NULL,
                                                   efi_blob_source,
                                                   "EFI",
                                                   "Boot",
                                                   DEFAULT_EFI_BLOB,
                                                   NULL);
        }

        if (!did_put) {
                DECLARE_OOM();
                return false;
        }

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
        FREE_IF_SET(sd_class_config.efi_blob_source);
        FREE_IF_SET(sd_class_config.loader_config);
        if (sd_class_config.copy_pairs) {
                nc_hashmap_free(sd_class_config.copy_pairs);
                sd_class_config.copy_pairs = NULL;
        }
        sd_class_config.secure_boot = false;
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

        item_name = string_printf("%s-%s-%s-%d.conf",
                                  prefix,
                                  kernel->meta.ktype,
                                  kernel->meta.version,
                                  kernel->meta.release);

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
        const CbmDeviceProbe *root_dev = NULL;
        const char *os_name = NULL;
        autofree(char) *old_conf = NULL;
        autofree(CbmWriter) *writer = CBM_WRITER_INIT;

        conf_path = get_entry_path_for_kernel((BootManager *)manager, kernel);

        /* Ensure all the relevant directories exist */
        if (!sd_class_ensure_dirs(manager)) {
                LOG_FATAL("Failed to create required directories");
                return false;
        }

        if (!cbm_writer_open(writer)) {
                DECLARE_OOM();
                abort();
        }

        /* Build the options for the entry */
        root_dev = boot_manager_get_root_device((BootManager *)manager);
        if (!root_dev) {
                LOG_FATAL("Root device unknown, this should never happen! %s", kernel->source.path);
                return false;
        }

        os_name = boot_manager_get_os_name((BootManager *)manager);

        /* Standard title + linux lines */
        cbm_writer_append_printf(writer, "title %s\n", os_name);
        cbm_writer_append_printf(writer,
                                 "linux /EFI/%s/%s\n",
                                 KERNEL_NAMESPACE,
                                 kernel->target.path);
        /* Optional initrd */
        if (kernel->target.initrd_path) {
                cbm_writer_append_printf(writer,
                                         "initrd /EFI/%s/%s\n",
                                         KERNEL_NAMESPACE,
                                         kernel->target.initrd_path);
        }
        /* Add the root= section */
        if (root_dev->part_uuid) {
                cbm_writer_append_printf(writer, "options root=PARTUUID=%s ", root_dev->part_uuid);
        } else {
                cbm_writer_append_printf(writer, "options root=UUID=%s ", root_dev->uuid);
        }
        /* Add LUKS information if relevant */
        if (root_dev->luks_uuid) {
                cbm_writer_append_printf(writer, "rd.luks.uuid=%s ", root_dev->luks_uuid);
        }

        /* Finish it off with the command line options */
        cbm_writer_append_printf(writer, "%s\n", kernel->meta.cmdline);
        cbm_writer_close(writer);

        if (cbm_writer_error(writer) != 0) {
                DECLARE_OOM();
                abort();
        }

        /* If our new config matches the old config, just return. */
        if (file_get_text(conf_path, &old_conf)) {
                if (streq(old_conf, writer->buffer)) {
                        return true;
                }
        }

        if (!file_set_text(conf_path, writer->buffer)) {
                LOG_FATAL("Failed to create loader entry for: %s [%s]",
                          kernel->source.path,
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
                item_name = string_printf("timeout %d\ndefault %s-%s-%s-%d\n",
                                          timeout,
                                          prefix,
                                          kernel->meta.ktype,
                                          kernel->meta.version,
                                          kernel->meta.release);
        } else {
                item_name = string_printf("default %s-%s-%s-%d\n",
                                          prefix,
                                          kernel->meta.ktype,
                                          kernel->meta.version,
                                          kernel->meta.release);
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
        NcHashmapIter iter = { 0 };
        nc_hashmap_iter_init(sd_class_config.copy_pairs, &iter);
        __cbm_unused__ const char *source = NULL;
        const char *target = NULL;

        /* Catch this in the install */
        if (!nc_file_exists(sd_class_config.efi_blob_source)) {
                return true;
        }

        while (nc_hashmap_iter_next(&iter, (void **)&target, (void **)&source)) {
                if (!nc_file_exists(target)) {
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

        NcHashmapIter iter = { 0 };
        nc_hashmap_iter_init(sd_class_config.copy_pairs, &iter);
        const char *source = NULL;
        const char *target = NULL;

        /* Catch this in the install */
        if (!nc_file_exists(sd_class_config.efi_blob_source)) {
                return true;
        }

        while (nc_hashmap_iter_next(&iter, (void **)&target, (void **)&source)) {
                if (nc_file_exists(target) && !cbm_files_match(source, target)) {
                        return true;
                }
        }

        return false;
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

        NcHashmapIter iter = { 0 };
        nc_hashmap_iter_init(sd_class_config.copy_pairs, &iter);
        const char *source = NULL;
        const char *target = NULL;

        /* Iterate all sources and blit them to disk atomically */
        while (nc_hashmap_iter_next(&iter, (void **)&target, (void **)&source)) {
                if (!copy_file_atomic(source, target, 00644)) {
                        LOG_FATAL("Failed to install %s: %s", target, strerror(errno));
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

        NcHashmapIter iter = { 0 };
        nc_hashmap_iter_init(sd_class_config.copy_pairs, &iter);
        const char *source = NULL;
        const char *target = NULL;

        /* Iterate all sources and write only if they changed */
        while (nc_hashmap_iter_next(&iter, (void **)&target, (void **)&source)) {
                if (cbm_files_match(source, target)) {
                        continue;
                }
                if (!copy_file_atomic(source, target, 00644)) {
                        LOG_FATAL("Failed to install %s: %s", target, strerror(errno));
                        return false;
                }
        }

        cbm_sync();

        return true;
}

bool sd_class_remove(const BootManager *manager)
{
        if (!manager) {
                return false;
        }

        NcHashmapIter iter = { 0 };
        nc_hashmap_iter_init(sd_class_config.copy_pairs, &iter);
        __cbm_unused__ const char *source = NULL;
        const char *target = NULL;

        /* Iterate all targets and remove them*/
        while (nc_hashmap_iter_next(&iter, (void **)&target, (void **)&source)) {
                if (nc_file_exists(target) && unlink(target) < 0) {
                        LOG_FATAL("Failed to remove %s: %s", target, strerror(errno));
                }
        }
        cbm_sync();

        /* We call multiple syncs in case something goes wrong in removal, where we could be seeing
         * an ESP umount after */
        if (nc_file_exists(sd_class_config.vendor_dir) && !nc_rm_rf(sd_class_config.vendor_dir)) {
                LOG_FATAL("Failed to remove vendor dir: %s", strerror(errno));
                return false;
        }
        cbm_sync();

        /* Delete our loader config file */
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

int sd_class_get_capabilities(__cbm_unused__ const BootManager *manager)
{
        /* Very trivial bootloader, we support UEFI/GPT only */
        return BOOTLOADER_CAP_GPT | BOOTLOADER_CAP_UEFI;
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
