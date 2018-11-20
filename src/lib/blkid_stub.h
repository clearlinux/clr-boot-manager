/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2017-2018 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#pragma once

#define _GNU_SOURCE
#include <blkid.h>

/**
 * Defines the vtable used for all blkid operations within clr-boot-manager.
 * The default internal vtable will pass through all operations to libblkid.
 */
typedef struct CbmBlkidOps {
        /* Probe functions */
        blkid_probe (*probe_new_from_filename)(const char *filename);
        int (*probe_enable_superblocks)(blkid_probe pr, int enable);
        int (*probe_set_superblocks_flags)(blkid_probe pr, int flags);
        int (*probe_enable_partitions)(blkid_probe pr, int enable);
        int (*probe_set_partitions_flags)(blkid_probe pr, int flags);
        int (*probe_lookup_value)(blkid_probe pr, const char *name, const char **data, size_t *len);
        int (*do_safeprobe)(blkid_probe pr);
        void (*free_probe)(blkid_probe pr);

        /* Partition functions */
        blkid_partlist (*probe_get_partitions)(blkid_probe pr);
        int (*partlist_numof_partitions)(blkid_partlist ls);
        blkid_partition (*partlist_get_partition)(blkid_partlist ls, int n);
        unsigned long long (*partition_get_flags)(blkid_partition par);
        const char *(*partition_get_uuid)(blkid_partition par);

        /* Partition table functions */
        blkid_parttable (*partlist_get_table)(blkid_partlist ls);
        const char *(*parttable_get_type)(blkid_parttable tab);

        /* Misc functions */
        int (*devno_to_wholedisk)(dev_t dev, char *diskname, size_t len, dev_t *diskdevno);
} CbmBlkidOps;

/**
 * Define an empty blkid_probe for testing
 */
#define CBM_BLKID_PROBE_NULL ((blkid_probe)0)

/**
 * Define a "set" blkid_probe for testing
 */
#define CBM_BLKID_PROBE_SET ((blkid_probe)1)

/**
 * Define an empty blkid_partlist for testing
 */
#define CBM_BLKID_PARTLIST_NULL ((blkid_partlist)0)

/**
 * Define a "set" blkid_partlist for testing
 */
#define CBM_BLKID_PARTLIST_SET ((blkid_partlist)1)

/**
 * Define an empty blkid_partition for testing
 */
#define CBM_BLKID_PARTITION_NULL ((blkid_partition)0)

/**
 * Define a "set" blkid_partition for testing
 */
#define CBM_BLKID_PARTITION_SET ((blkid_partition)1)

/**
 * Define a "set" blkid_parttable for testing
 */
#define CBM_BLKID_PARTTABLE_SET ((blkid_parttable)1)

/**
 * Define an empty blkid_parttable for testing
 */
#define CBM_BLKID_PARTTABLE_NULL ((blkid_parttable)0)

/**
 * Reset the blkid vtable
 */
void cbm_blkid_reset_vtable(void);

/**
 * Set the vfunc table used for all blkid operations within clr-boot-manager
 *
 * @note Passing null has the same effect as calling cbm_blkid_reset
 * The vtable will be checked to ensure that it is valid at this point, so
 * only call this when the vtable is fully populated.
 */
void cbm_blkid_set_vtable(CbmBlkidOps *ops);

/**
 * Probe related wrappers
 */
blkid_probe cbm_blkid_new_probe_from_filename(const char *filename);
int cbm_blkid_probe_enable_superblocks(blkid_probe pr, int enable);
int cbm_blkid_probe_set_superblocks_flags(blkid_probe pr, int flags);
int cbm_blkid_probe_enable_partitions(blkid_probe pr, int enable);
int cbm_blkid_probe_set_partitions_flags(blkid_probe pr, int flags);
int cbm_blkid_do_safeprobe(blkid_probe pr);
int cbm_blkid_probe_lookup_value(blkid_probe pr, const char *name, const char **data, size_t *len);
void cbm_blkid_free_probe(blkid_probe pr);

/**
 * Partition related wrappers
 */
blkid_partlist cbm_blkid_probe_get_partitions(blkid_probe pr);
int cbm_blkid_partlist_numof_partitions(blkid_partlist ls);
blkid_partition cbm_blkid_partlist_get_partition(blkid_partlist ls, int n);
unsigned long long cbm_blkid_partition_get_flags(blkid_partition par);
const char *cbm_blkid_partition_get_uuid(blkid_partition par);

/**
 * Partition table related wrappers
 */
blkid_parttable cbm_blkid_partlist_get_table(blkid_partlist ls);
const char *cbm_blkid_parttable_get_type(blkid_parttable tab);

/**
 * Misc related wrappers
 */
int cbm_blkid_devno_to_wholedisk(dev_t dev, char *diskname, size_t len, dev_t *diskdevno);

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
