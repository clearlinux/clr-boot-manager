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

#pragma once

#include "bootman.h"

typedef bool (*boot_loader_init)(const BootManager *);
typedef bool (*boot_loader_install_kernel)(const BootManager *, const Kernel *);
typedef bool (*boot_loader_remove_kernel)(const BootManager *, const Kernel *);
typedef bool (*boot_loader_set_default_kernel)(const BootManager *, const Kernel *kernel);
typedef bool (*boot_loader_needs_update)(const BootManager *);
typedef bool (*boot_loader_needs_install)(const BootManager *);
typedef bool (*boot_loader_install)(const BootManager *);
typedef bool (*boot_loader_update)(const BootManager *);
typedef bool (*boot_loader_remove)(const BootManager *);
typedef void (*boot_loader_destroy)(const BootManager *);

/**
 * Virtual BootLoader provider
 */
typedef struct BootLoader {
        const char *name;                                  /**<Name of the implementation */
        boot_loader_init init;                             /**<Init function */
        boot_loader_install_kernel install_kernel;         /**<Install a given kernel */
        boot_loader_remove_kernel remove_kernel;           /**<Remove a given kernel */
        boot_loader_set_default_kernel set_default_kernel; /**<Set the default kernel */
        boot_loader_needs_update needs_update;             /**<Check if an update is required */
        boot_loader_needs_install needs_install;           /**<Check if an install is required */
        boot_loader_install install;                       /**<Install this bootloader */
        boot_loader_update update;                         /**<Update this bootloader */
        boot_loader_remove remove;   /**<Remove this bootloader from the disk */
        boot_loader_destroy destroy; /**<Perform necessary cleanups */
} BootLoader;

#define __cbm_export__ __attribute__((visibility("default")))

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
