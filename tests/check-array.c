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
#include <malloc.h>
#include <stdlib.h>

#include "nica/array.c"
#include "nica/util.c"

START_TEST(nc_array_new_check)
{
        NcArray *array = NULL;

        array = nc_array_new();
        fail_if(!array, "Failed to allocate new array");
        fail_if(array->data, "array->data is not NULL after new");
        fail_if(array->len != 0, "array->len is not 0 after new");
        nc_array_free(&array, NULL);
}
END_TEST

START_TEST(nc_array_free_check)
{
        NcArray *array = NULL;

        nc_array_free(&array, NULL);
        fail_if(array, "Free changed NULL array to non NULL");
        /* Check to see if array free on NULL segfaults */
        nc_array_free(NULL, NULL);
        array = nc_array_new();
        fail_if(!array, "Failed to allocate new array");
        nc_array_free(&array, NULL);
        fail_if(array, "Failed to set array to NULL");
}
END_TEST

static inline void nc_array_free_fun(void *p)
{
        free(p);
}

START_TEST(nc_array_add_check)
{
        NcArray *array = NULL;
        int data1 = 1;
        int data2 = 2;
        int *data3 = NULL;

        fail_if(nc_array_add(NULL, &data1), "Added data to NULL array");
        array = nc_array_new();
        fail_if(!array, "Failed to allocate new array");
        fail_if(nc_array_add(array, NULL), "Added NULL data to array");
        fail_if(!nc_array_add(array, &data1), "Failed to add data1 to array");
        fail_if(!array->data, "Failed to allocate array->data");
        fail_if(array->len != 1, "Failed to update array->len with the size of the array");
        fail_if(*((int *)array->data[0]) != 1, "Failed to store correct data value to array");
        array->len = (uint16_t)(0 - 1);
        fail_if(nc_array_add(array, &data1), "Able to add more than max number of elements");
        array->len = 1;
        /* Test resize */
        fail_if(!nc_array_add(array, &data2), "Failed to add second element to array");
        fail_if(!array->data, "Failed to keep array->data");
        fail_if(array->len != 2, "Failed to update array->len with new size");
        fail_if(*((int *)array->data[0]) != 1, "Changed the first array element");
        fail_if(*((int *)array->data[1]) != 2, "Failed to set the second array element");
        nc_array_free(&array, NULL);
        fail_if(array, "Failed to set array to NULL 1");
        data3 = malloc(sizeof(int));
        fail_if(!data3, "Failed to allocate data");
        *data3 = 3;
        array = nc_array_new();
        fail_if(!array, "Failed to allocate new array");
        fail_if(!nc_array_add(array, data3), "Failed to add pointer data");
        fail_if(*((int *)array->data[0]) != 3,
                "Failed to store correct pointer data value to array");
        nc_array_free(&array, nc_array_free_fun);
        fail_if(array, "Failed to set array to NULL 2");
}
END_TEST

START_TEST(nc_array_get_check)
{
        NcArray *array = NULL;
        int data1 = 1;

        array = nc_array_new();
        fail_if(!array, "Failed to allocate new array");
        fail_if(nc_array_get(NULL, 0), "Got data from NULL array");
        fail_if(nc_array_get(array, 0), "Got data from empty array");
        fail_if(!nc_array_add(array, &data1), "Failed to add data1 to array");
        fail_if(*((int *)nc_array_get(array, 0)) != 1, "Failed to get correct value for element 0");
        fail_if(nc_array_get(array, 1), "Got data past end of array");
        nc_array_free(&array, NULL);
        fail_if(array, "Failed to set array to NULL");
}
END_TEST

START_TEST(nc_array_check)
{
        NcArray *array = NULL;
        char *value;
        char *element;
        void *f;
        bool r;

        array = nc_array_new();
        fail_if(array == NULL, "Failed to allocate memory for NcArray");
        element = strdup("test");
        fail_if(!element, "Failed to allocate memory for array item");
        r = nc_array_add(NULL, element);
        fail_if(r, "Added element to NULL array");
        r = nc_array_add(array, NULL);
        fail_if(r, "Added NULL element to array");
        r = nc_array_add(array, element);
        fail_if(r == false, "Failed to add element to NcArray");
        fail_if(array->len != 1, "Failed to get correct value for number of elements in array");

        f = nc_array_get(NULL, 0);
        fail_if(f, "Got value from NULL array");
        f = nc_array_get(array, (uint16_t)(array->len + 1));
        fail_if(f, "Got value from index bigger than maximum index");
        value = (char *)nc_array_get(array, 0);

        fail_if(value == NULL, "Failed to get value from NcArray");

        fail_if(strcmp(value, "test") != 0, "Failed to retrieve the stored value");

        nc_array_free(&array, nc_array_free_fun);
        fail_if(array != NULL, "Failed to free NcArray");
}
END_TEST

static int sort_strings(const void *a, const void *b)
{
        return strcmp(*(char **)a, *(char **)b);
}

static int sort_strings_reverse(const void *a, const void *b)
{
        return strcmp(*(char **)b, *(char **)a);
}

START_TEST(nc_array_sort_check)
{
        NcArray *array = NULL;

        array = nc_array_new();
        fail_if(!array, "Failed to allocate memory for NcArray");

        fail_if(!nc_array_add(array, "gamma"), "Failed to add to array");
        fail_if(!nc_array_add(array, "delta"), "Failed to add to array");
        fail_if(!nc_array_add(array, "beta"), "Failed to add to array");
        fail_if(!nc_array_add(array, "alpha"), "Failed to add to array");

        fail_if(array->len != 4, "Array length invalid");

        fail_if(!streq(nc_array_get(array, 0), "gamma"), "Invalid ordering in array #1");
        fail_if(!streq(nc_array_get(array, 1), "delta"), "Invalid ordering in array #2");
        fail_if(!streq(nc_array_get(array, 2), "beta"), "Invalid ordering in array #3");
        fail_if(!streq(nc_array_get(array, 3), "alpha"), "Invalid ordering in array #4");

        /* Alpha sort them */
        nc_array_qsort(array, sort_strings);

        fail_if(!streq(nc_array_get(array, 0), "alpha"), "Invalid sort ordering in array #1");
        fail_if(!streq(nc_array_get(array, 1), "beta"), "Invalid sort ordering in array #2");
        fail_if(!streq(nc_array_get(array, 2), "delta"), "Invalid sort ordering in array #3");
        fail_if(!streq(nc_array_get(array, 3), "gamma"), "Invalid sort ordering in array #4");

        /* Flip them back now */
        nc_array_qsort(array, sort_strings_reverse);
        fail_if(!streq(nc_array_get(array, 0), "gamma"), "Invalid reverse ordering in array #1");
        fail_if(!streq(nc_array_get(array, 1), "delta"), "Invalid reverse ordering in array #2");
        fail_if(!streq(nc_array_get(array, 2), "beta"), "Invalid reverse ordering in array #3");
        fail_if(!streq(nc_array_get(array, 3), "alpha"), "Invalid reverse ordering in array #4");

        nc_array_free(&array, NULL);
        fail_if(array != NULL, "Failed to free NcArray");
}
END_TEST

int main(void)
{
        int number_failed;
        Suite *s;
        SRunner *sr;
        TCase *tc;

        s = suite_create("nc_array");
        tc = tcase_create("nc_array_functions");
        tcase_add_test(tc, nc_array_new_check);
        tcase_add_test(tc, nc_array_free_check);
        tcase_add_test(tc, nc_array_add_check);
        tcase_add_test(tc, nc_array_get_check);
        tcase_add_test(tc, nc_array_check);
        tcase_add_test(tc, nc_array_sort_check);
        suite_add_tcase(s, tc);

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
