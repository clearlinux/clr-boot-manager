/*
 * This file is part of libnica.
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * libnica is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE
#include <check.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "nica/hashmap.c"
#include "nica/inifile.c"

START_TEST(nc_inifile_open_test)
{
        autofree(NcHashmap) *f = NULL;
        const char *t_path = TOP_DIR "/tests/data/ini/wellformed.ini";

        f = nc_ini_file_parse(t_path);
        fail_if(f == NULL, "Failed to parse wellformed.ini");
}
END_TEST

START_TEST(nc_inifile_good_test)
{
        const char *wellformed[] = { TOP_DIR "/tests/data/ini/wellformed.ini",
                                     TOP_DIR "/tests/data/ini/valid_padding.ini" };

        for (size_t i = 0; i < sizeof(wellformed) / sizeof(wellformed[0]); i++) {
                autofree(NcHashmap) *f = NULL;
                char *ret = NULL;

                f = nc_ini_file_parse(wellformed[i]);
                fail_if(f == NULL, "Failed to parse wellformed.ini");

                fail_if(!nc_hashmap_contains(f, "John"), "INI File missing \"John\" section");

                ret = nc_hashmap_get(nc_hashmap_get(f, "John"), "alive");
                fail_if(!ret, "Failed to get known value from INI file");
                fail_if(!streq(ret, "true"), "Incorrect value in INI file");

                fail_if(!nc_hashmap_contains(f, "Alice"), "INI File missing \"Alice\" section");
                ret = nc_hashmap_get(nc_hashmap_get(f, "Alice"), "alive");
                fail_if(!ret, "Failed to get known value from INI file");
                fail_if(!streq(ret, "false"), "Incorrect value in INI file #2");

                ret = nc_hashmap_get(nc_hashmap_get(f, "John"), "Random");
                fail_if(ret, "Got unexpected key in section");

                ret = nc_hashmap_get(nc_hashmap_get(f, "Bob"), "Random");
                fail_if(ret, "Got unexpected section");
        }
}
END_TEST

START_TEST(nc_inifile_bad_test)
{
        const char *t_path = TOP_DIR "/tests/data/ini/sectionless.ini";
        autofree(NcHashmap) *f = NULL;

        f = nc_ini_file_parse(t_path);
        fail_if(f != NULL, "Parsed illegal sectionless INI file");

        t_path = TOP_DIR "/tests/data/ini/empty_key.ini";
        f = nc_ini_file_parse(t_path);
        fail_if(f != NULL, "Parsed illegal INI file with empty keys");

        t_path = TOP_DIR "/tests/data/ini/just_assign.ini";
        f = nc_ini_file_parse(t_path);
        fail_if(f != NULL, "Parsed illegal assign-only INI file");

        t_path = TOP_DIR "/tests/data/ini/broken_section_start.ini";
        f = nc_ini_file_parse(t_path);
        fail_if(f != NULL, "Parsed illegal broken-section-start INI File");

        t_path = TOP_DIR "/tests/data/ini/broken_section_end.ini";
        f = nc_ini_file_parse(t_path);
        fail_if(f != NULL, "Parsed illegal broken-section-end INI File");
}
END_TEST

static Suite *core_suite(void)
{
        Suite *s = NULL;
        TCase *tc = NULL;

        s = suite_create("nc_inifile");
        tc = tcase_create("nc_inifile_functions");
        tcase_add_test(tc, nc_inifile_open_test);
        tcase_add_test(tc, nc_inifile_good_test);
        tcase_add_test(tc, nc_inifile_bad_test);
        suite_add_tcase(s, tc);

        return s;
}

int main(void)
{
        Suite *s;
        SRunner *sr;
        int fail;

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
