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

#define _GNU_SOURCE

#include <sys/types.h>

/**
 * A CbmCbmDeviceProbe is the result of a cbm_probe_path operation, caching
 * fields useful to clr-boot-manager in terms of partition analysis.
 */
typedef struct CbmDeviceProbe {
        char *uuid;      /**< UUID for all partition types */
        char *part_uuid; /**< PartUUID for GPT partitions */
        dev_t dev;       /**< The device itself */
} CbmDeviceProbe;

/**
 * Probe the given path for all relevant information
 */
CbmDeviceProbe *cbm_probe_path(const char *path);

/**
 * Free an existing probe
 */
void cbm_probe_free(CbmDeviceProbe *probe);
