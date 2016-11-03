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
#include "nica/hashmap.c"
#include <check.h>
#include <stdlib.h>

START_TEST(nc_hashmap_new_check)
{
        NcHashmap *map = NULL;

        map = nc_hashmap_new(NULL, NULL);
        fail_if(!map, "Failed to allocate new hashmap");
        fail_if(nc_hashmap_size(map) != 0, "Hashmap size is not 0 after new");
        nc_hashmap_free(map);
}
END_TEST

START_TEST(nc_hashmap_simple_check)
{
        NcHashmap *map = NULL;
        bool b;
        void *val = NULL;

        map = nc_hashmap_new(nc_simple_hash, nc_simple_compare);
        fail_if(!map, "Failed to allocate new hashmap");

        for (int i = 0; i < 1000; i++) {
                b = nc_hashmap_put(map, NC_HASH_KEY(i), NC_HASH_VALUE(i));
                fail_if(!b, "Failed to add integer to hashmap");
        }
        fail_if(nc_hashmap_size(map) != 1000, "Hashmap size invalid after 1000 elements");

        for (int i = 300; i < 700; i++) {
                b = nc_hashmap_remove(map, NC_HASH_KEY(i));
                fail_if(!b, "Failed to remove known integer from from hashmap");
        }

        fail_if(nc_hashmap_size(map) != 600, "Hashmap size invalid after 400 removals");

        val = nc_hashmap_get(map, NC_HASH_KEY(302));
        fail_if(val, "Value should not be returned from hashmap after removal");

        val = nc_hashmap_get(map, NC_HASH_KEY(802));
        fail_if(!val, "Value should be returned from hashmap for known key");
        fail_if(NC_UNHASH_VALUE(val) != 802, "Value returned from hashmap was incorrect");

        fail_if(!nc_hashmap_steal(map, NC_HASH_KEY(802)), "Failed to steal key/value");
        fail_if(nc_hashmap_contains(map, NC_HASH_KEY(802)), "Stolen key still exists");

        nc_hashmap_free(map);
        map = NULL;

        fail_if(nc_hashmap_size(map) >= 0, "Incorrect size returned for NULL hashmap");
}
END_TEST

START_TEST(nc_hashmap_dupe_check)
{
        NcHashmap *map = NULL;
        void *val = NULL;

        map = nc_hashmap_new(nc_simple_hash, nc_simple_compare);

        fail_if(!nc_hashmap_put(map, "name", "not important"),
                "Failed to put to hashmap first time!");
        val = nc_hashmap_get(map, "name");
        fail_if(!val, "Failed to get name!");
        fail_if(!streq(val, "not important"), "Returned value does not match");
        val = NULL;

        fail_if(!nc_hashmap_put(map, "name", "ikey"), "Failed to replace with second value");
        val = nc_hashmap_get(map, "name");
        fail_if(!streq(val, "ikey"), "Second return doesn't match expectation");
        nc_hashmap_free(map);
}
END_TEST

START_TEST(nc_hashmap_dupe_alloc_check)
{
        NcHashmap *map = NULL;
        void *val = NULL;
        void *val2 = NULL;

        map = nc_hashmap_new_full(nc_string_hash, nc_string_compare, free, free);

        fail_if(!nc_hashmap_put(map, strdup("name"), strdup("not important")),
                "Failed to put to hashmap first time!");
        val = nc_hashmap_get(map, "name");
        fail_if(!val, "Failed to get name!");
        fail_if(!streq(val, "not important"), "Returned value does not match");

        fail_if(!nc_hashmap_put(map, strdup("name"), strdup("ikey")),
                "Failed to replace with second value");
        val2 = nc_hashmap_get(map, "name");
        fail_if(!streq(val2, "ikey"), "Second return doesn't match expectation");
        nc_hashmap_free(map);
}
END_TEST

START_TEST(nc_hashmap_string_check)
{
        NcHashmap *map = NULL;
        bool b;
        void *val = NULL;

        map = nc_hashmap_new(nc_string_hash, nc_string_compare);
        fail_if(!map, "Failed to allocate new hashmap");

        b = nc_hashmap_put(map, "John", NC_HASH_VALUE(12));
        fail_if(!b, "Failed to put entry into map");
        b = nc_hashmap_put(map, "Lucy", NC_HASH_VALUE(42));
        fail_if(!b, "Failed to put entry into map");
        b = nc_hashmap_put(map, "Bob", NC_HASH_VALUE(19012));
        fail_if(!b, "Failed to put entry into map");
        b = nc_hashmap_put(map, "Sarah", NC_HASH_VALUE(83));
        fail_if(!b, "Failed to put entry into map");

        val = nc_hashmap_get(map, "John");
        fail_if(!val, "Failed to get known key from hashmap");
        fail_if(NC_UNHASH_VALUE(val) != 12, "Failed to get correct value from hashmap");

        val = nc_hashmap_get(map, "Lucy");
        fail_if(!val, "Failed to get known key from hashmap");
        fail_if(NC_UNHASH_VALUE(val) != 42, "Failed to get correct value from hashmap");

        val = nc_hashmap_get(map, "Bob");
        fail_if(!val, "Failed to get known key from hashmap");
        fail_if(NC_UNHASH_VALUE(val) != 19012, "Failed to get correct value from hashmap");

        val = nc_hashmap_get(map, "Sarah");
        fail_if(!val, "Failed to get known key from hashmap");
        fail_if(NC_UNHASH_VALUE(val) != 83, "Failed to get correct value from hashmap");

        nc_hashmap_free(map);
}
END_TEST

START_TEST(nc_hashmap_iter_check)
{
        NcHashmap *map = NULL;
        NcHashmapIter iter;
        bool b;
        int count = 0;
        void *key = NULL;
        void *value = NULL;

        map = nc_hashmap_new(NULL, NULL);
        fail_if(!map, "Failed to allocate new hashmap");

        for (int i = 0; i < 5000; i++) {
                b = nc_hashmap_put(map, NC_HASH_KEY(i), NC_HASH_KEY(i));
                fail_if(!b, "Failed to insert key into hashmap");
        }

        fail_if(nc_hashmap_size(map) != 5000, "Invalid hashmap size after 5000 elements");

        nc_hashmap_iter_init(map, &iter);
        while (nc_hashmap_iter_next(&iter, (void **)&key, (void **)&value)) {
                fail_if(NC_UNHASH_KEY(key) != NC_UNHASH_VALUE(value),
                        "Mismatched key/value pair in iteration");
                ++count;
        }
        fail_if(count != 5000, "Did not iterate all hashmap elements");

        count = 0;
        for (int i = 2000; i < 4000; i++) {
                b = nc_hashmap_remove(map, NC_HASH_KEY(i));
                fail_if(!b, "Failed to remove known integer key from hashmap");
        }

        nc_hashmap_iter_init(map, &iter);
        key = value = NULL;
        while (nc_hashmap_iter_next(&iter, &key, &value)) {
                unsigned int k = NC_UNHASH_KEY(key);
                fail_if(NC_UNHASH_VALUE(value) != k,
                        "Mismatched post-removal key/value pair in iteration");
                fail_if(k >= 2000 && k < 4000, "Key/value not removed from hashtable");
                ++count;
        }
        fail_if(count != 3000, "Did not iterate all 2000 elements");
        fail_if(nc_hashmap_size(map) != 3000, "Invalid hashmap size after removals");

        nc_hashmap_free(map);
}
END_TEST

static int free_count = 0;

static inline void free_helper(void *p)
{
        free((void *)p);
        ++free_count;
}

START_TEST(nc_hashmap_alloc_check)
{
        NcHashmap *map = NULL;
        char *str = NULL;
        void *val = NULL;
        bool b;

        map = nc_hashmap_new_full(nc_string_hash, nc_string_compare, free_helper, NULL);
        fail_if(!map, "Failed to allocate new hashmap");

        fail_if(!(str = strdup("Key 1"), "Allocation problem"));
        fail_if(!nc_hashmap_put(map, str, str), "Failed to insert into hashmap");

        fail_if(!(str = strdup("Key 2"), "Allocation problem"));
        fail_if(!nc_hashmap_put(map, str, str), "Failed to insert into hashmap");

        val = nc_hashmap_get(map, "Key 1");
        fail_if(!val, "Failed to get known value from hashmap");
        fail_if(strcmp(val, "Key 1") != 0, "Key 1 does not match");
        val = NULL;

        val = nc_hashmap_get(map, "Key 2");
        fail_if(!val, "Failed to get known value from hashmap");
        fail_if(strcmp(val, "Key 2") != 0, "Key 2 does not match");

        b = nc_hashmap_remove(map, "Key 2");
        fail_if(!b, "Failed to remove known key from hashmap");
        fail_if(free_count != 1, "Failed to free element from hashmap");

        nc_hashmap_free(map);
        fail_if(free_count != 2, "Failed to free last element from hashmap");
}
END_TEST

static Suite *nc_hashmap_suite(void)
{
        Suite *s = NULL;
        TCase *tc = NULL;

        s = suite_create("nc_hashmap");
        tc = tcase_create("nc_hashmap_functions");
        tcase_add_test(tc, nc_hashmap_new_check);
        tcase_add_test(tc, nc_hashmap_simple_check);
        tcase_add_test(tc, nc_hashmap_string_check);
        tcase_add_test(tc, nc_hashmap_iter_check);
        tcase_add_test(tc, nc_hashmap_alloc_check);
        tcase_add_test(tc, nc_hashmap_dupe_check);
        tcase_add_test(tc, nc_hashmap_dupe_alloc_check);
        suite_add_tcase(s, tc);

        return s;
}

int main(void)
{
        int number_failed;
        Suite *s;
        SRunner *sr;

        s = nc_hashmap_suite();
        sr = srunner_create(s);
        srunner_run_all(sr, CK_VERBOSE);
        number_failed = srunner_ntests_failed(sr);
        srunner_free(sr);

        return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
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
