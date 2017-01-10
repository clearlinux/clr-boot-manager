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
#include <stdlib.h>

#include "log.h"
#include "os-release.h"

START_TEST(cbm_os_release_test_quoted)
{
        const char *quote_file = TOP_DIR "/tests/data/solus.os-release";
        autofree(CbmOsRelease) *os_release = NULL;

        os_release = cbm_os_release_new(quote_file);
        fail_if(!os_release, "Failed to parse os-release file");

        fail_if(!streq(cbm_os_release_get_value(os_release, OS_RELEASE_NAME), "Solus"),
                "Invalid os-release name");
        fail_if(!streq(cbm_os_release_get_value(os_release, OS_RELEASE_ID), "solus"),
                "Invalid os-release ID");
}
END_TEST

START_TEST(cbm_os_release_test_unquoted)
{
        const char *quote_file = TOP_DIR "/tests/data/clear.os-release";
        autofree(CbmOsRelease) *os_release = NULL;

        os_release = cbm_os_release_new(quote_file);
        fail_if(!os_release, "Failed to parse os-release file");

        fail_if(!streq(cbm_os_release_get_value(os_release, OS_RELEASE_NAME),
                       "Clear Linux Software for Intel Architecture"),
                "Invalid os-release name");

        fail_if(!streq(cbm_os_release_get_value(os_release, OS_RELEASE_ID), "clear-linux-os"),
                "Invalid os-release ID");
}
END_TEST

static Suite *core_suite(void)
{
        Suite *s = NULL;
        TCase *tc = NULL;

        s = suite_create("cbm_os_release");
        tc = tcase_create("cbm_os_release_functions");
        tcase_add_test(tc, cbm_os_release_test_quoted);
        tcase_add_test(tc, cbm_os_release_test_unquoted);
        suite_add_tcase(s, tc);

        return s;
}

int main(void)
{
        Suite *s;
        SRunner *sr;
        int fail;

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
