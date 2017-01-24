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

#include <blkid.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "log.h"
#include "probe.h"
#include "util.h"

/**
 * Factory function to convert a dev_t to the full device path
 */
static char *cbm_devnode_to_devpath(dev_t dev)
{
        autofree(char) *c = NULL;
        if (asprintf(&c, "/dev/block/%u:%u", major(dev), minor(dev)) < 0) {
                return NULL;
        }
        return realpath(c, NULL);
}

CbmDeviceProbe *cbm_probe_path(const char *path)
{
        CbmDeviceProbe probe = { 0 };
        CbmDeviceProbe *ret = NULL;
        autofree(char) *devnode = NULL;
        struct stat st = { 0 };
        blkid_probe blk_probe = NULL;
        const char *value = NULL;

        if (stat(path, &st) != 0) {
                LOG_ERROR("Path does not exist: %s", path);
                return NULL;
        }
        if (major(st.st_dev) == 0) {
                LOG_ERROR("Invalid block device: %s", path);
                return NULL;
        }
        probe.dev = st.st_dev;

        devnode = cbm_devnode_to_devpath(probe.dev);
        if (!devnode) {
                DECLARE_OOM();
                return NULL;
        }

        blk_probe = blkid_new_probe_from_filename(devnode);
        if (!blk_probe) {
                fprintf(stderr, "Unable to probe %u:%u", major(st.st_dev), minor(st.st_dev));
                return NULL;
        }

        blkid_probe_enable_superblocks(blk_probe, 1);
        blkid_probe_set_superblocks_flags(blk_probe, BLKID_SUBLKS_TYPE | BLKID_SUBLKS_UUID);
        blkid_probe_enable_partitions(blk_probe, 1);
        blkid_probe_set_partitions_flags(blk_probe, BLKID_PARTS_ENTRY_DETAILS);

        if (blkid_do_safeprobe(blk_probe) != 0) {
                LOG_ERROR("Error probing filesystem: %s", strerror(errno));
                goto clean;
        }

        if (blkid_probe_lookup_value(blk_probe, "PART_ENTRY_UUID", &value, NULL) == 0) {
                probe.part_uuid = strdup(value);
                if (!probe.part_uuid) {
                        DECLARE_OOM();
                        goto clean;
                }
        }

        if (blkid_probe_lookup_value(blk_probe, "UUID", &value, NULL) == 0) {
                probe.uuid = strdup(value);
                if (!probe.uuid) {
                        DECLARE_OOM();
                        goto clean;
                }
        }

        if (!probe.part_uuid && !probe.uuid) {
                LOG_ERROR("Unable to find UUID for %s: %s", devnode, strerror(errno));
        }

        ret = calloc(1, sizeof(CbmDeviceProbe));
        if (!ret) {
                DECLARE_OOM();
                return NULL;
        }
        *ret = probe;

clean:
        blkid_free_probe(blk_probe);
        return ret;
}

void cbm_probe_free(CbmDeviceProbe *probe)
{
        if (!probe) {
                return;
        }

        free(probe->uuid);
        free(probe->part_uuid);
        free(probe);
        return;
}
