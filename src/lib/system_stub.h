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

#pragma once

#define _GNU_SOURCE

#include <stdbool.h>
#include <sys/types.h>

/**
 * Defines the vtable used for all systen operations within clr-boot-manager.
 * The default internal vtable will pass through all operations to the standard
 * library.
 */
typedef struct CbmSystemOps {
        /* fs functions */
        int (*mount)(const char *source, const char *target, const char *filesystemtype,
                     unsigned long mountflags, const void *data);
        int (*umount)(const char *target);

        /* wrap cbm lib functions */
        bool (*is_mounted)(const char *target);
        char *(*get_mountpoint_for_device)(const char *device);

        /* exec family */
        int (*system)(const char *command);

        /* dev utility */
        char *(*devnode_to_devpath)(dev_t t);
        const char *(*get_sysfs_path)(void);
        const char *(*get_devfs_path)(void);
} CbmSystemOps;

/**
 * Reset the system vtable
 */
void cbm_system_reset_vtable(void);

/**
 * Set the vfunc table used for all system operations within clr-boot-manager
 *
 * @note Passing null has the same effect as calling cbm_system_reset
 * The vtable will be checked to ensure that it is valid at this point, so
 * only call this when the vtable is fully populated.
 */
void cbm_system_set_vtable(CbmSystemOps *ops);

/**
 * Wrap the mount syscall
 */
int cbm_system_mount(const char *source, const char *target, const char *filesystemtype,
                     unsigned long mountflags, const void *data);

/**
 * Determine if the given mount point is already mounted
 */
bool cbm_system_is_mounted(const char *target);

/**
 * Get the mountpoint for the given device path
 */
char *cbm_system_get_mountpoint_for_device(const char *device);

/**
 * Wrap the umount syscall
 */
int cbm_system_umount(const char *target);

/**
 * Wrap the system() call
 */
int cbm_system_system(const char *command);

/**
 * Resolve the path for a given dev_t
 */
char *cbm_system_devnode_to_devpath(dev_t d);

/**
 * Help mocking by allowing /sys to be overridden
 */
const char *cbm_system_get_sysfs_path(void);

/**
 * Help mocking by allowing /dev to be overridden
 */
const char *cbm_system_get_devfs_path(void);

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
