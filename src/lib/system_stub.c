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

#include "system_stub.h"

#include <assert.h>
#include <stdlib.h>
#include <sys/mount.h>

#include "files.h"
#include "log.h"

/**
 * Factory function to convert a dev_t to the full device path
 * This is the default internal function
 */
static char *cbm_devnode_to_devpath(dev_t dev)
{
        if (major(dev) == 0) {
                LOG_ERROR("Invalid block device: %u:%u", major(dev), minor(dev));
                return NULL;
        }

        autofree(char) *c = NULL;
        if (asprintf(&c, "/dev/block/%u:%u", major(dev), minor(dev)) < 0) {
                return NULL;
        }
        return realpath(c, NULL);
}

static const char *cbm_get_sysfs_path(void)
{
        return "/sys";
}

static const char *cbm_get_devfs_path(void)
{
        return "/dev";
}

/**
 * Default vtable for system call passthrough
 */
static CbmSystemOps default_system_ops = {
        .mount = mount,
        .umount = umount,
        .system = system,
        .is_mounted = cbm_is_mounted,
        .get_mountpoint_for_device = cbm_get_mountpoint_for_device,
        .devnode_to_devpath = cbm_devnode_to_devpath,
        .get_sysfs_path = cbm_get_sysfs_path,
        .get_devfs_path = cbm_get_devfs_path,
};

/**
 * Pointer to the currently active vtable
 */
static CbmSystemOps *system_ops = &default_system_ops;

void cbm_system_reset_vtable(void)
{
        system_ops = &default_system_ops;
}

void cbm_system_set_vtable(CbmSystemOps *ops)
{
        if (!ops) {
                cbm_system_reset_vtable();
        } else {
                system_ops = ops;
        }
        /* Ensure the vtable is valid at this point. */
        assert(system_ops->mount != NULL);
        assert(system_ops->umount != NULL);
        assert(system_ops->is_mounted != NULL);
        assert(system_ops->get_mountpoint_for_device != NULL);
        assert(system_ops->system != NULL);
        assert(system_ops->devnode_to_devpath != NULL);
        assert(system_ops->get_sysfs_path != NULL);
        assert(system_ops->get_devfs_path != NULL);
}

int cbm_system_mount(const char *source, const char *target, const char *filesystemtype,
                     unsigned long mountflags, const void *data)
{
        return system_ops->mount(source, target, filesystemtype, mountflags, data);
}

int cbm_system_umount(const char *target)
{
        return system_ops->umount(target);
}

int cbm_system_system(const char *command)
{
        return system_ops->system(command);
}

bool cbm_system_is_mounted(const char *target)
{
        return system_ops->is_mounted(target);
}

char *cbm_system_get_mountpoint_for_device(const char *device)
{
        return system_ops->get_mountpoint_for_device(device);
}

char *cbm_system_devnode_to_devpath(dev_t d)
{
        return system_ops->devnode_to_devpath(d);
}

const char *cbm_system_get_sysfs_path()
{
        return system_ops->get_sysfs_path();
}

const char *cbm_system_get_devfs_path()
{
        return system_ops->get_devfs_path();
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
