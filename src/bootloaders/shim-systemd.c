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

#include "bootman.h"
#include "bootloader.h"
#include "config.h"

/*
 * This file implements 2-stage bootloader configuration in which shim is used as
 * the first stage bootloader and systemd-boot as the second stage bootloader.
 *
 * This implementation uses the following ESP layout:
 *
 *     /EFI/
 *          Boot/
 *              BOOTX64.EFI         <-- whatever was there before
 *
 *      /org.clearlinux/
 *          bootloaderx64.efi       <-- shim
 *          loaderx64.efi           <-- systemd-boot bootloader
 *          mmx64.efi               <-- MOK mgr
 *          fbx64.efi               <-- MOK mgr
 *
 *          kernel/                 <-- kernels
 *              kernel-org.clearlinux.....
 *              ...
 *
 *      /loader/                    <-- systemd-boot config
 *          entries/                <-- boot menu entries
 *              Clear-linux...conf
 *              ...
 *          loader.conf             <-- bootloader config
 *
 * Note that default bootloader at /EFI/Boot/BOOTX64.EFI is never modified.
 * Instead, we create an EFI BootXXX variable and put it first in the BootOrder
 * EFI variable.
 */

static bool _shim_systemd_install_kernel(const BootManager *manager, const Kernel *kernel);
static bool _shim_systemd_remove_kernel(const BootManager *manager, const Kernel *kernel);
static bool _shim_systemd_set_default_kernel(const BootManager *manager, const Kernel *kernel);
static bool _shim_systemd_needs_install(const BootManager *manager);
static bool _shim_systemd_needs_update(const BootManager *manager);
static bool _shim_systemd_install(const BootManager *manager);
static bool _shim_systemd_update(const BootManager *manager);
static bool _shim_systemd_remove(const BootManager *manager);
static bool _shim_systemd_init(const BootManager *manager);
static void _shim_systemd_destroy(const BootManager *manager);
static int  _shim_systemd_get_capabilities(const BootManager *manager);

__cbm_export__ const BootLoader shim_systemd_bootloader = {
        .name = "systemd",
        .init = _shim_systemd_init,
        .install_kernel = _shim_systemd_install_kernel,
        .remove_kernel = _shim_systemd_remove_kernel,
        .set_default_kernel = _shim_systemd_set_default_kernel,
        .needs_install = _shim_systemd_needs_install,
        .needs_update = _shim_systemd_needs_update,
        .install = _shim_systemd_install,
        .update = _shim_systemd_update,
        .remove = _shim_systemd_remove,
        .destroy = _shim_systemd_destroy,
        .get_capabilities = _shim_systemd_get_capabilities
};

#if UINTPTR_MAX == 0xffffffffffffffff
#       define EFI_SUFFIX       "x64.efi"
#else
#       define EFI_SUFFIX       "ia32.efi"
#endif

/* Layout entries, see the layout description at the top of the file. */
#define SHIM_SRC_DIR            "/usr/lib/shim"
#define SHIM_SRC                SHIM_SRC_DIR "/" "shim" EFI_SUFFIX
#define MM_SRC                  SHIM_SRC_DIR "/" "mm" EFI_SUFFIX
#define FB_SRC                  SHIM_SRC_DIR "/" "fb" EFI_SUFFIX
#define SYSTEMD_SRC_DIR         "/usr/lib/systemd/boot/efi"
#define SYSTEMD_SRC             SYSTEMD "/" "systemd-boot" EFI_SUFFIX
#define DST_DIR                 BOOT_DIRECTORY "/" KERNEL_NAMESPACE
#define SHIM_DST                DST_DIR "/" "bootloader" EFI_SUFFIX
#define SYSTEMD_DST             DST_DIR "/" "loader" EFI_SUFFIX
#define KERNEL_DST_DIR          DST_DIR "/kernel"
#define SYSTEMD_CONFIG_DIR      BOOT_DIRECTORY "/loader"
#define SYSTEMD_CONFIG          SYSTEMD_CONFIG_DIR "/loader.conf"
#define SYSTEMD_ENTRIES         SYSTEMD_CONFIG_DIR "/entries"

static bool _shim_systemd_install_kernel(const BootManager *manager, const Kernel *kernel) {
        return true;
}

static bool _shim_systemd_remove_kernel(const BootManager *manager, const Kernel *kernel) {
        return true;
}

static bool _shim_systemd_set_default_kernel(const BootManager *manager, const Kernel *kernel) {
        return true;
}

static bool _shim_systemd_needs_install(const BootManager *manager) {
        return true;
}

static bool _shim_systemd_needs_update(const BootManager *manager) {
        return true;
}

static bool _shim_systemd_install(const BootManager *manager) {
        return true;
}

static bool _shim_systemd_update(const BootManager *manager) {
        return true;
}

static bool _shim_systemd_remove(const BootManager *manager) {
        return true;
}

static bool _shim_systemd_init(const BootManager *manager) {
        return true;
}

static void _shim_systemd_destroy(const BootManager *manager) {
        return true;
}

static int _shim_systemd_get_capabilities(const BootManager *manager) {
        return 0;
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
