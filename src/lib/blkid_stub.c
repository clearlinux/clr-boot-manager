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

#include "blkid_stub.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

/**
 * Ensure we check here for the blkid device being correct.
 */
static int cbm_blkid_devno_to_wholedisk_wrapped(dev_t dev, char *diskname, size_t len,
                                                dev_t *diskdevno)
{
        if (major(dev) == 0) {
                return -1;
        }
        return blkid_devno_to_wholedisk(dev, diskname, len, diskdevno);
}

/**
 * Default blkid ops vtable passes through to libblkid itself
 */
static CbmBlkidOps default_blkid_ops = {
        .probe_new_from_filename = blkid_new_probe_from_filename,
        .probe_enable_superblocks = blkid_probe_enable_superblocks,
        .probe_set_superblocks_flags = blkid_probe_set_superblocks_flags,
        .probe_enable_partitions = blkid_probe_enable_partitions,
        .probe_set_partitions_flags = blkid_probe_set_partitions_flags,
        .probe_lookup_value = blkid_probe_lookup_value,
        .do_safeprobe = blkid_do_safeprobe,
        .free_probe = blkid_free_probe,

        /* Partition functions */
        .probe_get_partitions = blkid_probe_get_partitions,
        .partlist_numof_partitions = blkid_partlist_numof_partitions,
        .partlist_get_partition = blkid_partlist_get_partition,
        .partition_get_flags = blkid_partition_get_flags,
        .partition_get_uuid = blkid_partition_get_uuid,

        /* Partition table functions */
        .partlist_get_table = blkid_partlist_get_table,
        .parttable_get_type = blkid_parttable_get_type,

        /* Misc */
        .devno_to_wholedisk = cbm_blkid_devno_to_wholedisk_wrapped,
};

/**
 * Pointer to the currently active vtable
 */
static CbmBlkidOps *blkid_ops = &default_blkid_ops;

void cbm_blkid_reset_vtable(void)
{
        blkid_ops = &default_blkid_ops;
}

void cbm_blkid_set_vtable(CbmBlkidOps *ops)
{
        if (!ops) {
                cbm_blkid_reset_vtable();
        } else {
                blkid_ops = ops;
        }
        /* Ensure the vtable is valid at this point. */
        assert(blkid_ops->probe_new_from_filename != NULL);
        assert(blkid_ops->probe_enable_superblocks != NULL);
        assert(blkid_ops->probe_set_superblocks_flags != NULL);
        assert(blkid_ops->probe_enable_partitions != NULL);
        assert(blkid_ops->probe_set_partitions_flags != NULL);
        assert(blkid_ops->probe_lookup_value != NULL);
        assert(blkid_ops->do_safeprobe != NULL);
        assert(blkid_ops->free_probe != NULL);

        /* partition functions */
        assert(blkid_ops->probe_get_partitions != NULL);
        assert(blkid_ops->partlist_numof_partitions != NULL);
        assert(blkid_ops->partlist_get_partition != NULL);
        assert(blkid_ops->partition_get_flags != NULL);
        assert(blkid_ops->partition_get_uuid != NULL);

        /* partition table functions */
        assert(blkid_ops->partlist_get_table != NULL);
        assert(blkid_ops->parttable_get_type != NULL);

        /* misc */
        assert(blkid_ops->devno_to_wholedisk != NULL);
}

/**
 * Probe functions
 */
blkid_probe cbm_blkid_new_probe_from_filename(const char *filename)
{
        return blkid_ops->probe_new_from_filename(filename);
}

int cbm_blkid_probe_enable_superblocks(blkid_probe pr, int enable)
{
        return blkid_ops->probe_enable_superblocks(pr, enable);
}

int cbm_blkid_probe_set_superblocks_flags(blkid_probe pr, int flags)
{
        return blkid_ops->probe_set_superblocks_flags(pr, flags);
}

int cbm_blkid_probe_enable_partitions(blkid_probe pr, int enable)
{
        return blkid_ops->probe_enable_partitions(pr, enable);
}

int cbm_blkid_probe_set_partitions_flags(blkid_probe pr, int flags)
{
        return blkid_ops->probe_set_partitions_flags(pr, flags);
}

int cbm_blkid_do_safeprobe(blkid_probe pr)
{
        return blkid_ops->do_safeprobe(pr);
}

int cbm_blkid_probe_lookup_value(blkid_probe pr, const char *name, const char **data, size_t *len)
{
        return blkid_ops->probe_lookup_value(pr, name, data, len);
}

void cbm_blkid_free_probe(blkid_probe pr)
{
        blkid_ops->free_probe(pr);
}

/**
 * Partition functions
 */
blkid_partlist cbm_blkid_probe_get_partitions(blkid_probe pr)
{
        return blkid_ops->probe_get_partitions(pr);
}

int cbm_blkid_partlist_numof_partitions(blkid_partlist ls)
{
        return blkid_ops->partlist_numof_partitions(ls);
}

blkid_partition cbm_blkid_partlist_get_partition(blkid_partlist ls, int n)
{
        return blkid_ops->partlist_get_partition(ls, n);
}

unsigned long long cbm_blkid_partition_get_flags(blkid_partition par)
{
        return blkid_ops->partition_get_flags(par);
}

const char *cbm_blkid_partition_get_uuid(blkid_partition par)
{
        return blkid_ops->partition_get_uuid(par);
}

/**
 * Partition table related wrappers
 */
blkid_parttable cbm_blkid_partlist_get_table(blkid_partlist ls)
{
        return blkid_ops->partlist_get_table(ls);
}

const char *cbm_blkid_parttable_get_type(blkid_parttable tab)
{
        return blkid_ops->parttable_get_type(tab);
}

/**
 * Misc functions
 */
int cbm_blkid_devno_to_wholedisk(dev_t dev, char *diskname, size_t len, dev_t *diskdevno)
{
        return blkid_ops->devno_to_wholedisk(dev, diskname, len, diskdevno);
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
