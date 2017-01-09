/*
 * This file is part of clr-boot-manager.
 *
 * This file masks private implementation details to share throughout the
 * libcbm implementation for the purposes of organisational sanity.
 *
 * Copyright © 2016 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#pragma once

#ifndef _BOOTMAN_INTERNAL_
#error This file can only be included within libcbm!
#endif

#include <stdbool.h>

#include "bootloader.h"
#include "bootman.h"

struct BootManager {
        char *kernel_dir;             /**<Kernel directory */
        const BootLoader *bootloader; /**<Selected bootloader */
        char *vendor_prefix;          /**<Vendor prefix, i.e. com.blah */
        char *os_name;                /**<Operating system name */
        char *abs_bootdir;            /**<Real boot dir */
        SystemKernel sys_kernel;      /**<Native kernel info, if any */
        bool have_sys_kernel;         /**<Whether sys_kernel is set */
        bool can_mount;               /**<Are we allowed to mount? */
        bool image_mode;              /**<Are we in image mode? */
        SystemConfig *sysconfig;      /**<System configuration */
        char *cmdline;                /**<Additional cmdline to append */
};

/**
 * Internal check to see if the kernel blob is installed
 */
bool boot_manager_is_kernel_installed_internal(const BootManager *manager, const Kernel *kernel);

/**
 * Internal function to install the kernel blob itself
 */
bool boot_manager_install_kernel_internal(const BootManager *manager, const Kernel *kernel);

/**
 * Internal function to remove the kernel blob itself
 */
bool boot_manager_remove_kernel_internal(const BootManager *manager, const Kernel *kernel);

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
