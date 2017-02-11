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

#pragma once

#include "system_stub.h"

static inline int test_mount(__cbm_unused__ const char *source, __cbm_unused__ const char *target,
                             __cbm_unused__ const char *filesystemtype,
                             __cbm_unused__ unsigned long mountflags,
                             __cbm_unused__ const void *data)
{
        return 0;
}

static inline int test_umount(__cbm_unused__ const char *target)
{
        return 0;
}

static inline int test_system(__cbm_unused__ const char *command)
{
        return 0;
}

static inline bool test_is_mounted(__cbm_unused__ const char *target)
{
        return false;
}

static inline char *test_get_mountpoint_for_device(__cbm_unused__ const char *device)
{
        return NULL;
}

static inline char *test_devnode_to_devpath(__cbm_unused__ dev_t d)
{
        return string_printf("%s/dev/testRoot", TOP_BUILD_DIR "/tests/update_playground");
}

static inline const char *test_get_sysfs_path(void)
{
        return TOP_BUILD_DIR "/tests/update_playground/sys";
}

static const char *test_get_devfs_path(void)
{
        return TOP_BUILD_DIR "/tests/update_playground/dev";
}

/**
 * Default vtable for testing. Copy into a local struct and override specific
 * fields.
 */
CbmSystemOps SystemTestOps = {
        .mount = test_mount,
        .umount = test_umount,
        .system = test_system,
        .is_mounted = test_is_mounted,
        .get_mountpoint_for_device = test_get_mountpoint_for_device,
        .devnode_to_devpath = test_devnode_to_devpath,
        .get_sysfs_path = test_get_sysfs_path,
        .get_devfs_path = test_get_devfs_path,
};

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
