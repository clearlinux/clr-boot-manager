/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2016 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE
#include <check.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "util.h"

#include "files.h"
#include "log.h"
#include "nica/files.h"

START_TEST(bootman_uuid_test)
{
        if (geteuid() != 0) {
                LOG_INFO("Skipping UUID test as root privileges are required");
                return;
        }
        const char *path = TOP_DIR "/tests/data/hashfile";
        autofree(char) *puuid = NULL;

        puuid = get_part_uuid(path);
        fail_if(!puuid, "Failed to get filesystem UUID");

        LOG_INFO("PUUID: %s", puuid);
}
END_TEST

START_TEST(bootman_find_boot)
{
        if (!nc_file_exists("/sys/firmware/efi")) {
                LOG_INFO("Skipping UEFI host-specific test");
                return;
        }
        autofree(char) *boot = NULL;

        boot = get_boot_device();
        fail_if(!boot, "Unable to determine a boot device");
}
END_TEST

START_TEST(bootman_mount_test)
{
        if (!nc_file_exists("/proc/self/mounts")) {
                LOG_INFO("Skipping mount test as /proc/self/mounts is absent");
                return;
        }
        fail_if(!cbm_is_mounted("/", NULL), "Apparently / not mounted. Question physics.");
        fail_if(cbm_is_mounted("/,^roflcopter", NULL),
                "Non-existent path mounted. Or you have a genuinely weird path");
}
END_TEST

static Suite *core_suite(void)
{
        Suite *s = NULL;
        TCase *tc = NULL;

        s = suite_create("bootman_files");
        tc = tcase_create("bootman_files");
        tcase_add_test(tc, bootman_hash_test);
        tcase_add_test(tc, bootman_uuid_test);
        tcase_add_test(tc, bootman_mount_test);
        tcase_add_test(tc, bootman_find_boot);
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
