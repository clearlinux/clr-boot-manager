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
#include <check.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "util.h"

#include "files.h"
#include "log.h"
#include "nica/files.h"
#include "system-harness.h"

START_TEST(bootman_match_test)
{
        const char *source_match = TOP_DIR "/tests/data/match";
        const char *good_match = TOP_DIR "/tests/data/match1";
        const char *bad_match_data = TOP_DIR "/tests/data/nomatch1";
        const char *bad_match_len = TOP_DIR "/tests/data/nomatch2";
        /* In a clean environment, anyway. */
        const char *non_exist_path = "PATHTHATWONT@EXIST!";

        /* Known good */
        fail_if(!cbm_files_match(source_match, good_match), "Known matches failed to match");

        /* Known different data */
        fail_if(cbm_files_match(source_match, bad_match_data),
                "Shouldn't match files with different data");

        /* Known different data + length */
        fail_if(cbm_files_match(source_match, bad_match_len),
                "Shouldn't match files with different length");

        /* Known missing target, with source present */
        fail_if(cbm_files_match(source_match, non_exist_path),
                "Shouldn't match with non existent target");

        /* Known missing source with existing target */
        fail_if(cbm_files_match(non_exist_path, source_match),
                "Shouldn't match with non existent source");

        /* Known missing both */
        fail_if(cbm_files_match(non_exist_path, non_exist_path),
                "Shouldn't match non existent files");
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
        fail_if(!cbm_is_mounted("/"), "Apparently / not mounted. Question physics.");
        fail_if(cbm_is_mounted("/,^roflcopter"),
                "Non-existent path mounted. Or you have a genuinely weird path");
}
END_TEST

static Suite *core_suite(void)
{
        Suite *s = NULL;
        TCase *tc = NULL;

        s = suite_create("bootman_files");
        tc = tcase_create("bootman_files");
        tcase_add_test(tc, bootman_match_test);
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
        cbm_system_set_vtable(&SystemTestOps);

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
