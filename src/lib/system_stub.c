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

/**
 * Default vtable for system call passthrough
 */
static CbmSystemOps default_system_ops = {
        .mount = mount, .umount = umount, .system = system,
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
        assert(system_ops->system != NULL);
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
