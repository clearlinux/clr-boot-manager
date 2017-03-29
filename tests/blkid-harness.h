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

#include "blkid_stub.h"

const char *DEFAULT_UUID = "Test-UUID";
const char *DEFAULT_PART_UUID = "Test-PartUUID";

/**
 * Probe functions
 */
static inline blkid_probe test_blkid_new_probe_from_filename(__cbm_unused__ const char *filename)
{
        return CBM_BLKID_PROBE_SET;
}

static inline int test_blkid_probe_enable_superblocks(__cbm_unused__ blkid_probe pr,
                                                      __cbm_unused__ int enable)
{
        return 0;
}

static inline int test_blkid_probe_set_superblocks_flags(__cbm_unused__ blkid_probe pr,
                                                         __cbm_unused__ int flags)
{
        return 0;
}

static inline int test_blkid_probe_enable_partitions(__cbm_unused__ blkid_probe pr,
                                                     __cbm_unused__ int enable)
{
        return 0;
}

static inline int test_blkid_probe_set_partitions_flags(__cbm_unused__ blkid_probe pr,
                                                        __cbm_unused__ int flags)
{
        return 0;
}

static inline int test_blkid_do_safeprobe(__cbm_unused__ blkid_probe pr)
{
        return 0;
}

static inline int test_blkid_probe_lookup_value(__cbm_unused__ blkid_probe pr, const char *name,
                                                const char **data, size_t *len)
{
        if (!name || !data) {
                return -1;
        }
        if (streq(name, "UUID")) {
                *data = DEFAULT_UUID;
        } else if (streq(name, "PART_ENTRY_UUID")) {
                *data = DEFAULT_PART_UUID;
        } else {
                return -1;
        }
        if (!*data) {
                abort();
        }
        if (len) {
                *len = strlen(*data);
        }
        return 0;
}

static inline void test_blkid_free_probe(__cbm_unused__ blkid_probe pr)
{
}

/**
 * Partition functions
 */
static inline blkid_partlist test_blkid_probe_get_partitions(__cbm_unused__ blkid_probe pr)
{
        return CBM_BLKID_PARTLIST_SET;
}

static inline int test_blkid_partlist_numof_partitions(__cbm_unused__ blkid_partlist ls)
{
        return 2;
}

static inline blkid_partition test_blkid_partlist_get_partition(__cbm_unused__ blkid_partlist ls,
                                                                __cbm_unused__ int n)
{
        return CBM_BLKID_PARTITION_SET;
}

static inline unsigned long long test_blkid_partition_get_flags(__cbm_unused__ blkid_partition par)
{
        /* Prevents legacy testing */
        return 0;
}

static inline const char *test_blkid_partition_get_uuid(__cbm_unused__ blkid_partition par)
{
        return NULL;
}

static inline int test_blkid_devno_to_wholedisk(__cbm_unused__ dev_t dev,
                                                __cbm_unused__ char *diskname,
                                                __cbm_unused__ size_t len,
                                                __cbm_unused__ dev_t *diskdevno)
{
        /* Prevent legacy testing */
        return -1;
}

static inline blkid_parttable test_blkid_partlist_get_table(__cbm_unused__ blkid_partlist ls)
{
        /* Return a "valid" partition table */
        return CBM_BLKID_PARTTABLE_SET;
}

static inline const char *test_blkid_parttable_get_type(__cbm_unused__ blkid_parttable tab)
{
        /* Return correct gpt identifier */
        return "gpt";
}

/**
 * Default vtable for testing. Copy into a local struct and override specific
 * fields.
 */
CbmBlkidOps BlkidTestOps = {
        .probe_new_from_filename = test_blkid_new_probe_from_filename,
        .probe_enable_superblocks = test_blkid_probe_enable_superblocks,
        .probe_set_superblocks_flags = test_blkid_probe_set_superblocks_flags,
        .probe_enable_partitions = test_blkid_probe_enable_partitions,
        .probe_set_partitions_flags = test_blkid_probe_set_partitions_flags,
        .probe_lookup_value = test_blkid_probe_lookup_value,
        .do_safeprobe = test_blkid_do_safeprobe,
        .free_probe = test_blkid_free_probe,

        /* Partition functions */
        .probe_get_partitions = test_blkid_probe_get_partitions,
        .partlist_numof_partitions = test_blkid_partlist_numof_partitions,
        .partlist_get_partition = test_blkid_partlist_get_partition,
        .partition_get_flags = test_blkid_partition_get_flags,
        .partition_get_uuid = test_blkid_partition_get_uuid,

        /* Partition table functions */
        .partlist_get_table = test_blkid_partlist_get_table,
        .parttable_get_type = test_blkid_parttable_get_type,

        /* Misc */
        .devno_to_wholedisk = test_blkid_devno_to_wholedisk,
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
