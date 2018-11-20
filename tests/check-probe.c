/*
 * This file is part of clr-boot-manager.
 *
 * This test suite is designed to resolve issue #53:
 * https://github.com/ikeydoherty/clr-boot-manager/issues/53
 *
 * When writing the bootloader entries, clr-boot-manager will attempt to use
 * the PartUUID where applicable. Originally we would use if blkid reported
 * a valid PartUUID, resulting in root=PARTUUID= kernel parameters.
 *
 * However, it has been seen that blkid can and will report a PartUUID on a
 * non GPT system, resulting in a broken boot. i.e. /dev/disk/by-partuuid/$UUID
 * does not exist.
 *
 * For UEFI, GPT is only required for the EFI System Partition itself, however
 * no such limitation is placed on the rootfs. Thus, clr-boot-manager must
 * determine whether the disk for the rootfs is GPT or not, and *only* use
 * a PartUUID when it is definitely GPT.
 *
 * Copyright © 2016-2018 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE
#include <check.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#include "blkid_stub.h"
#include "bootloader.h"
#include "bootman.h"
#include "config.h"
#include "files.h"
#include "log.h"
#include "probe.h"

#include "blkid-harness.h"
#include "harness.h"
#include "system-harness.h"

#define PLAYGROUND_ROOT TOP_BUILD_DIR "/tests/update_playground"

/**
 * Restore the default testing vtables
 */
static void bootman_probe_set_default_vtables(void)
{
        cbm_blkid_set_vtable(&BlkidTestOps);
        cbm_system_set_vtable(&SystemTestOps);
}

/**
 * Coerce GPT lookup
 */
static inline int gpt_devno_to_wholedisk(__cbm_unused__ dev_t dev, __cbm_unused__ char *diskname,
                                         __cbm_unused__ size_t len, __cbm_unused__ dev_t *diskdevno)
{
        *diskdevno = makedev(8, 8);
        return 0;
}

/**
 * This will force the tests to use the GPT detection codepaths
 */
static CbmBlkidOps gpt_blkid_ops = {
        .probe_new_from_filename = test_blkid_new_probe_from_filename,
        .probe_enable_superblocks = test_blkid_probe_enable_superblocks,
        .probe_set_superblocks_flags = test_blkid_probe_set_superblocks_flags,
        .probe_enable_partitions = test_blkid_probe_enable_partitions,
        .probe_set_partitions_flags = test_blkid_probe_set_partitions_flags,
        .probe_lookup_value = test_blkid_probe_lookup_value,
        .do_safeprobe = test_blkid_do_safeprobe,
        .free_probe = test_blkid_free_probe,
        .probe_get_partitions = test_blkid_probe_get_partitions,
        .partlist_numof_partitions = test_blkid_partlist_numof_partitions,
        .partlist_get_partition = test_blkid_partlist_get_partition,
        .partition_get_flags = test_blkid_partition_get_flags,
        .partition_get_uuid = test_blkid_partition_get_uuid,
        .partlist_get_table = test_blkid_partlist_get_table,
        .parttable_get_type = test_blkid_parttable_get_type,
        .devno_to_wholedisk = gpt_devno_to_wholedisk,
};

static inline const char *mbr_parttable_get_type(__cbm_unused__ blkid_parttable tab)
{
        /* Return correct mbr identifier */
        return "mbr";
}
/**
 * This will force the tests to use the MBR detection codepaths
 */
static CbmBlkidOps mbr_blkid_ops = {
        .probe_new_from_filename = test_blkid_new_probe_from_filename,
        .probe_enable_superblocks = test_blkid_probe_enable_superblocks,
        .probe_set_superblocks_flags = test_blkid_probe_set_superblocks_flags,
        .probe_enable_partitions = test_blkid_probe_enable_partitions,
        .probe_set_partitions_flags = test_blkid_probe_set_partitions_flags,
        .probe_lookup_value = test_blkid_probe_lookup_value,
        .do_safeprobe = test_blkid_do_safeprobe,
        .free_probe = test_blkid_free_probe,
        .probe_get_partitions = test_blkid_probe_get_partitions,
        .partlist_numof_partitions = test_blkid_partlist_numof_partitions,
        .partlist_get_partition = test_blkid_partlist_get_partition,
        .partition_get_flags = test_blkid_partition_get_flags,
        .partition_get_uuid = test_blkid_partition_get_uuid,
        .partlist_get_table = test_blkid_partlist_get_table,
        .parttable_get_type = mbr_parttable_get_type,
        .devno_to_wholedisk = gpt_devno_to_wholedisk,
};

static void bootman_probe_set_gpt_vtables(void)
{
        /* override test ops for legacy testing */
        cbm_blkid_set_vtable(&gpt_blkid_ops);
        cbm_system_set_vtable(&SystemTestOps);
}

static void bootman_probe_set_mbr_vtables(void)
{
        /* override test ops for legacy testing */
        cbm_blkid_set_vtable(&mbr_blkid_ops);
        cbm_system_set_vtable(&SystemTestOps);
}

/**
 * Ensure we can detect GPT rootfs for a UEFI system.
 * Note that `set_test_system_legacy` is only responsible for creating the
 * root nodes, when we initialise the playground the UEFI nodes are also
 * created.
 */
START_TEST(bootman_probe_basic_gpt)
{
        static PlaygroundConfig config = { "4.2.1-121.kvm", NULL, 0, .uefi = true };
        autofree(BootManager) *m = NULL;
        bootman_probe_set_gpt_vtables();
        autofree(CbmDeviceProbe) *probe = NULL;

        /* Let harness prep the root */
        m = prepare_playground(&config);

        set_test_system_legacy();
        probe = cbm_probe_path(PLAYGROUND_ROOT);

        fail_if(!probe, "Failed to get probe for a valid rootfs");
        fail_if(!probe->gpt, "GPT UEFI root not detected as GPT");
        fail_if(!probe->part_uuid, "GPT UEFI root has no PartUUID detected");
        fail_if(!streq(probe->part_uuid, DEFAULT_PART_UUID),
                "Expected PartUUID '%s', got '%s'",
                DEFAULT_PART_UUID,
                probe->part_uuid);
}
END_TEST

/**
 * Much like the previous test, except that we force MBR detection for the root
 * disk
 */
START_TEST(bootman_probe_basic_mbr)
{
        static PlaygroundConfig config = { "4.2.1-121.kvm", NULL, 0, .uefi = true };
        autofree(BootManager) *m = NULL;
        bootman_probe_set_mbr_vtables();
        autofree(CbmDeviceProbe) *probe = NULL;

        /* Let harness prep the root */
        m = prepare_playground(&config);

        set_test_system_legacy();
        probe = cbm_probe_path(PLAYGROUND_ROOT);

        fail_if(!probe, "Failed to get probe for a valid rootfs");
        fail_if(probe->gpt, "MBR UEFI root not detected as MBR");
        fail_if(probe->part_uuid, "MBR UEFI root has a PartUUID detected");
        fail_if(!streq(probe->uuid, DEFAULT_UUID),
                "Expected UUID '%s', got '%s'",
                DEFAULT_UUID,
                probe->uuid);
}
END_TEST

/**
 * UEFI + unknown partition table
 */
START_TEST(bootman_probe_basic_none)
{
        static PlaygroundConfig config = { "4.2.1-121.kvm", NULL, 0, .uefi = true };
        autofree(BootManager) *m = NULL;
        bootman_probe_set_default_vtables();
        autofree(CbmDeviceProbe) *probe = NULL;

        /* Let harness prep the root */
        m = prepare_playground(&config);

        set_test_system_legacy();
        probe = cbm_probe_path(PLAYGROUND_ROOT);

        fail_if(!probe, "Failed to get probe for a valid rootfs");
        fail_if(probe->gpt, "Unknown UEFI root not detected as MBR");
        fail_if(probe->part_uuid, "Unknown UEFI root has a PartUUID detected");
        fail_if(!streq(probe->uuid, DEFAULT_UUID),
                "Expected UUID '%s', got '%s'",
                DEFAULT_UUID,
                probe->uuid);
}
END_TEST

static Suite *core_suite(void)
{
        Suite *s = NULL;
        TCase *tc = NULL;

        s = suite_create("bootman_probe");

        /* UEFI tests */
        tc = tcase_create("bootman_probe_basic_functions");
        tcase_add_test(tc, bootman_probe_basic_gpt);
        tcase_add_test(tc, bootman_probe_basic_mbr);
        tcase_add_test(tc, bootman_probe_basic_none);
        suite_add_tcase(s, tc);

        return s;
}

int main(void)
{
        Suite *s;
        SRunner *sr;
        int fail;

        /* syncing can be problematic during test suite runs */
        cbm_set_sync_filesystems(false);

        /* Ensure that logging is set up properly. */
        setenv("CBM_DEBUG", "1", 1);
        cbm_log_init(stderr);

        /* Turn off the EFI variable manipulation. */
        setenv("CBM_BOOTVAR_TEST_MODE", "yes", 1);

        s = core_suite();
        sr = srunner_create(s);
        srunner_run_all(sr, CK_VERBOSE);
        fail = srunner_ntests_failed(sr);
        srunner_free(sr);

        if (fail > 0) {
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
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
