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

#define _GNU_SOURCE

#include <linux/limits.h>

#include "bootloader.h"
#include "bootman.h"
#include "bootvar.h"
#include "config.h"
#include "files.h"
#include "nica/files.h"
#include "systemd-class.h"
#include <log.h>

/*
 * This file implements 2-stage bootloader configuration in which shim is used as
 * the first stage bootloader and systemd-boot as the second stage bootloader.
 *
 * This implementation uses the following ESP layout. KERNEL_NAMESPACE is set
 * with --with-kernel-namespace configure option and VENDOR_PREFIX is set using
 * --with-vendor-prefix.
 *
 *     /EFI/
 *          Boot/
 *              BOOTX64.EFI         <-- the fallback bootloader only modified if
 *                                      image is being created
 *
 *          KERNEL_NAMESPACE/
 *              bootloaderx64.efi       <-- shim
 *              loaderx64.efi           <-- systemd-boot bootloader
 *              mmx64.efi               <-- MOK manager
 *              fbx64.efi               <-- fallback bootloader
 *
 *              kernel/                 <-- kernels and initrds
 *                  kernel-KERNEL_NAMESPACE...
 *                  initrd-KERNEL_NAMESPACE...
 *                  ...
 *
 *      /loader/                    <-- systemd-boot config
 *          entries/                <-- boot menu entries
 *              VENDOR_PREFIX....conf
 *              ...
 *          loader.conf             <-- bootloader config
 *
 * Note that default bootloader at /EFI/Boot/BOOTX64.EFI is modified only when
 * bootable image is being created. This is a fallback scheme: using only
 * systemd as the last resort to boot. When the system is being updated, an EFI
 * boot entry is created (BootXXXX EFI variable) if it does not exist already.
 */

static const char *shim_systemd_get_kernel_destination(const BootManager *);
static bool shim_systemd_install_kernel(const BootManager *, const Kernel *);
static bool shim_systemd_remove_kernel(const BootManager *, const Kernel *);
static bool shim_systemd_set_default_kernel(const BootManager *, const Kernel *);
static bool shim_systemd_needs_install(const BootManager *);
static bool shim_systemd_needs_update(const BootManager *);
static bool shim_systemd_install(const BootManager *);
static bool shim_systemd_update(const BootManager *);
static bool shim_systemd_remove(const BootManager *);
static bool shim_systemd_init(const BootManager *);
static void shim_systemd_destroy(const BootManager *);
static int shim_systemd_get_capabilities(const BootManager *);

__cbm_export__ const BootLoader
    shim_systemd_bootloader = {.name = "systemd",
                               .init = shim_systemd_init,
                               .get_kernel_destination = shim_systemd_get_kernel_destination,
                               .install_kernel = shim_systemd_install_kernel,
                               .remove_kernel = shim_systemd_remove_kernel,
                               .set_default_kernel = shim_systemd_set_default_kernel,
                               .needs_install = shim_systemd_needs_install,
                               .needs_update = shim_systemd_needs_update,
                               .install = shim_systemd_install,
                               .update = shim_systemd_update,
                               .remove = shim_systemd_remove,
                               .destroy = shim_systemd_destroy,
                               .get_capabilities = shim_systemd_get_capabilities };

#if UINTPTR_MAX == 0xffffffffffffffff
#define EFI_SUFFIX "x64.efi"
#else
#define EFI_SUFFIX "ia32.efi"
#endif

/* Layout entries, see the layout description at the top of the file. */
#define SHIM_SRC_DIR "usr/lib/shim"
#define SHIM_SRC                                                                                   \
        SHIM_SRC_DIR                                                                               \
        "/"                                                                                        \
        "shim" EFI_SUFFIX
#define MM_SRC                                                                                     \
        SHIM_SRC_DIR                                                                               \
        "/"                                                                                        \
        "mm" EFI_SUFFIX
#define FB_SRC                                                                                     \
        SHIM_SRC_DIR                                                                               \
        "/"                                                                                        \
        "fb" EFI_SUFFIX
#define SYSTEMD_SRC_DIR "usr/lib/systemd/boot/efi"
#define SYSTEMD_SRC                                                                                \
        SYSTEMD_SRC_DIR                                                                            \
        "/"                                                                                        \
        "systemd-boot" EFI_SUFFIX
#define DST_DIR "/EFI/" KERNEL_NAMESPACE
#define SHIM_DST                                                                                   \
        DST_DIR                                                                                    \
        "/"                                                                                        \
        "bootloader" EFI_SUFFIX
#define SYSTEMD_DST                                                                                \
        DST_DIR                                                                                    \
        "/"                                                                                        \
        "loader" EFI_SUFFIX
#define KERNEL_DST_DIR DST_DIR "/kernel"
#define SYSTEMD_CONFIG_DIR "/loader"
#define SYSTEMD_CONFIG SYSTEMD_CONFIG_DIR "/loader.conf"
#define SYSTEMD_ENTRIES SYSTEMD_CONFIG_DIR "/entries"

/* path to fallback bootloader: /EFI/Boot/BOOT(X64|IA32).EFI */
#define EFI_FALLBACK_DIR "/EFI/Boot"
#define EFI_FALLBACK_PATH                                                                          \
        EFI_FALLBACK_DIR                                                                           \
        "/"                                                                                        \
        "BOOT" EFI_SUFFIX

static char *shim_src;
static char *shim_dst_host; /* as accessible by the CMB for file ops. */
static char *shim_dst_esp;  /* absolute location of shim on the ESP. */
static char *systemd_src;
static char *systemd_dst_host;
static int is_image_mode;
static int has_boot_rec = -1;

extern void sd_class_set_get_kernel_destination_impl(const char *(*)(const BootManager *));

static const char *shim_systemd_get_kernel_destination(__cbm_unused__ const BootManager *manager)
{
        return KERNEL_DST_DIR;
}

static bool shim_systemd_install_kernel(const BootManager *manager, const Kernel *kernel)
{
        return sd_class_install_kernel(manager, kernel);
}

static bool shim_systemd_remove_kernel(const BootManager *manager, const Kernel *kernel)
{
        return sd_class_remove_kernel(manager, kernel);
}

static bool shim_systemd_set_default_kernel(const BootManager *manager, const Kernel *kernel)
{
        /* this writes systemd config. systemd has the configuration paths
         * hardcoded, hence whatever sd_class is doing is OK. */
        return sd_class_set_default_kernel(manager, kernel);
}

static bool exists_identical(const char *path, const char *spath)
{
        if (!nc_file_exists(path)) {
                return false;
        }
        if (spath && !cbm_files_match(path, spath)) {
                return false;
        }
        return true;
}

static bool shim_systemd_needs_install(__cbm_unused__ const BootManager *manager)
{
        if (has_boot_rec < 0) {
                if (!is_image_mode) {
                        has_boot_rec = bootvar_has_boot_rec(BOOT_DIRECTORY, shim_dst_esp);
                } else {
                        has_boot_rec = 1;
                }
        }
        if (!exists_identical(shim_dst_host, NULL)) {
                return true;
        }
        if (!exists_identical(systemd_dst_host, NULL)) {
                return true;
        }
        return !has_boot_rec;
}

static bool shim_systemd_needs_update(__cbm_unused__ const BootManager *manager)
{
        if (has_boot_rec < 0) {
                if (!is_image_mode) {
                        has_boot_rec = bootvar_has_boot_rec(BOOT_DIRECTORY, shim_dst_esp);
                } else {
                        has_boot_rec = 1;
                }
        }
        if (!exists_identical(shim_dst_host, shim_src)) {
                return true;
        }
        if (!exists_identical(systemd_dst_host, systemd_src)) {
                return true;
        }
        return !has_boot_rec;
}

static bool make_layout(const BootManager *manager)
{
        char *boot_root = boot_manager_get_boot_dir((BootManager *)manager);
        char *path = NULL;
        path = string_printf("%s%s", boot_root, DST_DIR);
        if (!nc_mkdir_p(path, 00755)) {
                goto fail;
        }
        free(path);
        path = string_printf("%s%s", boot_root, KERNEL_DST_DIR);
        if (!nc_mkdir_p(path, 00755)) {
                goto fail;
        }
        free(path);
        path = string_printf("%s%s", boot_root, SYSTEMD_ENTRIES);
        if (!nc_mkdir_p(path, 00755)) {
                goto fail;
        }
        free(path);
        /* in case of image creation, override the fallback bootloader, so the
         * media will be bootable. */
        if (is_image_mode) {
                path = string_printf("%s%s", boot_root, EFI_FALLBACK_DIR);
                LOG_INFO("Image mode: creating dir for fallback: %s", path);
                if (!nc_mkdir_p(path, 00755)) {
                        goto fail;
                }
                free(path);
        }
        free(boot_root);
        return true;
fail:
        free(boot_root);
        if (path) {
                LOG_FATAL("Failed to make dir: %s", path);
                free(path);
        }
        return false;
}

/* Installs EFI fallback (default) bootloader at /EFI/Boot/BOOTX64.EFI */
static bool shim_systemd_install_fallback_bootloader(const BootManager *manager)
{
        char *boot_dir = boot_manager_get_boot_dir((BootManager *)manager);
        char *dst = string_printf("%s%s", boot_dir, EFI_FALLBACK_PATH);
        bool result = true;

        free(boot_dir);

        if (!copy_file_atomic(systemd_src, dst, 00644)) {
                LOG_FATAL("Cannot copy %s to %s", systemd_src, dst);
                result = false;
        }
        free(dst);
        return result;
}

static bool shim_systemd_install(const BootManager *manager)
{
        char varname[9];

        if (!make_layout(manager)) {
                LOG_FATAL("Cannot create layout");
                return false;
        }

        if (!copy_file_atomic(shim_src, shim_dst_host, 00644)) {
                LOG_FATAL("Cannot copy %s to %s", shim_src, shim_dst_host);
                return false;
        }
        if (!copy_file_atomic(systemd_src, systemd_dst_host, 00644)) {
                LOG_FATAL("Cannot copy %s to %s", systemd_src, systemd_dst_host);
                return false;
        }

        if (!is_image_mode) {
                if (!has_boot_rec) {
                        if (bootvar_create(BOOT_DIRECTORY, shim_dst_esp, varname, 9)) {
                                LOG_FATAL("Cannot create EFI variable (boot entry)");
                                return false;
                        }
                }
        } else {
                /* override the fallback bootloader in case it's the image mode,
                 * create EFI boot entry otherwise. */
                if (!shim_systemd_install_fallback_bootloader(manager)) {
                        return false;
                }
        }

        return true;
}

static bool shim_systemd_update(const BootManager *manager)
{
        return shim_systemd_install(manager);
}

static bool shim_systemd_remove(__cbm_unused__ const BootManager *manager)
{
        fprintf(stderr, "%s is not implemented\n", __func__);
        return true;
}

static bool shim_systemd_init(const BootManager *manager)
{
        size_t len;
        char *prefix, *boot_root;

        if (!boot_manager_is_image_mode((BootManager *)manager)) {
                if (bootvar_init()) {
                        return false;
                }
                is_image_mode = 0;
        } else {
                is_image_mode = 1;
        }

        /* init systemd-class since we're reusing it for kernel install.
         * specific values do not matter as long as sd_class is not used to
         * install the bootloaders themselves. */
        static BootLoaderConfig systemd_config = {.vendor_dir = "systemd",
                                                  .efi_dir = "/usr/lib/systemd/boot/efi",
                                                  .efi_blob = "systemd-boot" EFI_SUFFIX,
                                                  .name = "systemd-boot" };
        sd_class_init(manager, &systemd_config);
        sd_class_set_get_kernel_destination_impl(shim_systemd_get_kernel_destination);

        prefix = strdup(boot_manager_get_prefix((BootManager *)manager));
        len = strlen(prefix);
        if (len > 0 && prefix[len - 1] == '/') {
                prefix[len - 1] = '\0';
        }
        shim_src = string_printf("%s/%s", prefix, SHIM_SRC);
        systemd_src = string_printf("%s/%s", prefix, SYSTEMD_SRC);

        boot_root = boot_manager_get_boot_dir((BootManager *)manager);
        len = strlen(boot_root);
        /* SHIM_DST and SYSTEMD_DST are defined with leading '/', take extra
         * care to produce clean paths. */
        if (len > 0 && boot_root[len - 1] == '/') {
                boot_root[len - 1] = '\0';
        }
        shim_dst_host = string_printf("%s%s", boot_root, SHIM_DST);
        systemd_dst_host = string_printf("%s%s", boot_root, SYSTEMD_DST);

        shim_dst_esp = SHIM_DST;

        free(prefix);
        free(boot_root);

        return true;
}

static void shim_systemd_destroy(const BootManager *manager)
{
        free(shim_src);
        free(systemd_src);
        free(shim_dst_host);
        free(systemd_dst_host);
        if (!is_image_mode) {
                bootvar_destroy();
        }
        sd_class_destroy(manager);

        return;
}

static int shim_systemd_get_capabilities(__cbm_unused__ const BootManager *manager)
{
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
