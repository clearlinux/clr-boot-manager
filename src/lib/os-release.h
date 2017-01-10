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

#include "nica/hashmap.h"
#include "util.h"

typedef enum {
        OS_RELEASE_MIN = 0,
        OS_RELEASE_NAME,
        OS_RELEASE_VERSION,
        OS_RELEASE_ID,
        OS_RELEASE_VERSION_ID,
        OS_RELEASE_PRETTY_NAME,
        OS_RELEASE_ANSI_COLOR,
        OS_RELEASE_HOME_URL,
        OS_RELEASE_SUPPORT_URL,
        OS_RELEASE_BUG_REPORT_URL,
        OS_RELEASE_MAX,
} CbmOsReleaseKey;

/**
 * OsRelease is simply a hashmap with forced lower keys,
 * and some handy accessor methods.
 *
 * A CbmOsRelease is parsed from an /etc/os-release style file to provide
 * OS version and name information.
 */
typedef NcHashmap CbmOsRelease;

/**
 * Create a new CbmOsRelease by parsing the given os-release file
 * This method may return an empty CbmOsRelease map if there was a parsing
 * issue.
 */
CbmOsRelease *cbm_os_release_new(const char *path);

/**
 * Find the first os-release file in the standard locations within the
 * given root.
 * In the instance that no os-release files are found, or a parsing
 * error occurred, an empty CbmOsRelease will be returned.
 */
CbmOsRelease *cbm_os_release_new_for_root(const char *root);

/**
 * Return the value of a predefined field in the os-release file.
 * This string belongs to the CbmOsRelease instance and should not be
 * freed or modified in any way.
 * If you need to modify it, strdup it.
 *
 * This method will only ever return NULL if self is NULL or if the key is
 * within an invalid range.
 *
 * @param key The field to return a value for
 */
const char *cbm_os_release_get_value(CbmOsRelease *self, CbmOsReleaseKey key);

/**
 * Free a previously allocated CbmOsRelease
 */
void cbm_os_release_free(CbmOsRelease *self);

/* Convenience function */
DEF_AUTOFREE(CbmOsRelease, nc_hashmap_free)

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
