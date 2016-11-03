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
#include <fcntl.h>
#include <limits.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>

#include "nica/list.c"

START_TEST(nc_list_append_check)
{
        NcList *list = NULL;
        NcList *head = NULL;
        int data1 = 1;
        int data2 = 2;

        fail_if(!nc_list_append(&list, &data1), "Append for new list failed");
        head = list;
        fail_if(list->tail != list, "list and list->tail do not match after new list append");
        fail_if(list->next, "list->next is not NULL after new list append");
        fail_if(*((int *)(list->data)) != 1, "list->data is incorrect after new list append");
        fail_if(list->size != 1, "list->size not 1 after new list append");

        fail_if(!nc_list_append(&list, &data2), "Append for existing list failed");
        fail_if(head != list, "Append switched list head");
        fail_if(list->tail != list->next,
                "list->next and list->tail do not match after two appends");
        fail_if(list->next->next, "list->next->next is not NULL after two appends");
        fail_if(*((int *)(list->data)) != 1, "list->data is incorrect after two list appends");
        fail_if(*((int *)(list->next->data)) != 2,
                "list->next->data is incorrect after two list appends");
        fail_if(list->size != 2, "list->size not 2 after two list appends");

        nc_list_free(&list);
}
END_TEST

START_TEST(nc_list_prepend_check)
{
        NcList *list = NULL;
        NcList *tail = NULL;
        int data1 = 1;
        int data2 = 2;

        fail_if(!nc_list_prepend(&list, &data1), "Prepend for new list failed");
        tail = list;
        fail_if(list->tail != list, "list and list->tail do not match after new list prepend");
        fail_if(list->next, "list->next is not NULL after new list prepend");
        fail_if(*((int *)(list->data)) != 1, "list->data is incorrect after new list prepend");
        fail_if(list->size != 1, "list->size not 1 after new list prepend");

        fail_if(!nc_list_prepend(&list, &data2), "Prepend for existing list failed");
        fail_if(tail != list->next, "Prepend switched list next");
        fail_if(tail != list->tail, "Prepend switched list tail");
        fail_if(list->tail != list->next,
                "list->next and list->tail do not match after two prepends");
        fail_if(list->next->next, "list->next->next is not NULL after two prepends");
        fail_if(*((int *)(list->data)) != 2, "list->data is incorrect after two list prepends");
        fail_if(*((int *)(list->next->data)) != 1,
                "list->next->data is incorrect after two list prepends");
        fail_if(list->size != 2, "list->size not 2 after two list prepends");

        nc_list_free(&list);
}
END_TEST

START_TEST(nc_list_remove_check)
{
        NcList *list = NULL;
        int data1 = 1;
        int data2 = 2;
        int data3 = 3;
        int *data4 = NULL;
        int *data5 = NULL;

        fail_if(nc_list_remove(&list, &data1, false), "Removed from non existing list");
        fail_if(!nc_list_prepend(&list, &data1), "Prepend for new list failed");
        fail_if(nc_list_remove(&list, &data2, false), "Removed non existing element from list");
        fail_if(list->tail != list, "list and list->tail do not match after new list prepend");
        fail_if(list->next, "list->next is not NULL after new list prepend");
        fail_if(*((int *)(list->data)) != 1, "list->data is incorrect after new list prepend");
        fail_if(list->size != 1, "list->size not 1 after new list prepend");
        fail_if(!nc_list_remove(&list, &data1, false), "Unable to remove existing item from list");
        fail_if(list, "List not NULL after removal of only element");

        data4 = malloc(sizeof(int));
        data5 = malloc(sizeof(int));
        fail_if(!data4 || !data5, "Failed to allocate");
        *data4 = 4;
        *data5 = 5;
        fail_if(!nc_list_prepend(&list, &data1), "Prepend 1 for list failed");
        fail_if(!nc_list_append(&list, &data2), "Append 1 for list failed");
        fail_if(!nc_list_prepend(&list, &data3), "Prepend 2 for list failed");
        fail_if(!nc_list_append(&list, data4), "Append 2 for list failed");
        fail_if(!nc_list_prepend(&list, data5), "Prepend 3 for list failed");
        /* the list is = (*5, 3, 1, 2, *4) */
        fail_if(!nc_list_remove(&list, &data1, false), "Unable to remove data1 from list");
        fail_if(nc_list_remove(&list, &data1, false), "Able to remove data1 from list again");
        /* the list is = (*5, 3, 2, *4) */
        fail_if(*((int *)(list->data)) != 5, "list->data value incorrect");
        fail_if(list->size != 4, "list->size incorrect");
        fail_if(*((int *)(list->next->next->data)) != 2, "list->next->next->data value incorrect");
        fail_if(*((int *)(list->tail->data)) != 4, "list->tail->data value incorrect");
        fail_if(list->tail != list->next->next->next, "list->tail is incorrect");
        fail_if(!nc_list_remove(&list, data4, true), "Failed to remove data4 from list");
        /* the list is = (*5, 3, 2) */
        fail_if(*((int *)(list->data)) != 5, "list->data value incorrect");
        fail_if(list->size != 3, "list->size incorrect");
        fail_if(*((int *)(list->tail->data)) != 2, "list->tail->data value incorrect");
        fail_if(list->tail != list->next->next, "list->tail is incorrect");
        fail_if(!nc_list_remove(&list, data5, true), "Failed to remove data5 from list");
        /* the list is = (3, 2) */
        fail_if(*((int *)(list->data)) != 3, "list->data value incorrect");
        fail_if(list->size != 2, "list->size incorrect");
        fail_if(*((int *)(list->tail->data)) != 2, "list->tail->data value incorrect");
        fail_if(list->tail != list->next, "list->tail is incorrect");
        fail_if(!nc_list_remove(&list, &data3, false), "Failed to remove data3 from list");
        /* the list is = (2) */
        fail_if(*((int *)(list->data)) != 2, "list->data value incorrect");
        fail_if(list->size != 1, "list->size incorrect");
        fail_if(*((int *)(list->tail->data)) != 2, "list->tail->data value incorrect");
        fail_if(list->tail != list, "list->tail is incorrect");
        fail_if(!nc_list_remove(&list, &data2, false), "Failed to remove data2 from list");
        /* the list is = () */
        fail_if(list, "list is not NULL");
}
END_TEST

START_TEST(nc_list_foreach_check)
{
        NcList *list = NULL;
        NcList *i;
        int data1 = 1;
        int data2 = 2;
        int data3 = 3;
        int c = 1;

        fail_if(!nc_list_append(&list, &data1), "Append 1 for list failed");
        fail_if(!nc_list_append(&list, &data2), "Append 2 for list failed");
        fail_if(!nc_list_append(&list, &data3), "Append 3 for list failed");
        NC_LIST_FOREACH (list, i) {
                fail_if(*((int *)(i->data)) != c, "Failed to iterate list");
                c++;
        }

        nc_list_free(&list);
}
END_TEST

START_TEST(nc_list_free_check)
{
        NcList *list = NULL;
        int data1 = 1;
        int data2 = 2;
        int data3 = 3;

        nc_list_free(&list);
        fail_if(list, "null list returned non null after free");
        fail_if(!nc_list_append(&list, &data1), "Append 1 for list failed");
        fail_if(!nc_list_append(&list, &data2), "Append 2 for list failed");
        fail_if(!nc_list_append(&list, &data3), "Append 3 for list failed");
        nc_list_free(&list);
        fail_if(list, "non null list returned non null after free");
}
END_TEST

START_TEST(nc_list_free_all_check)
{
        NcList *list = NULL;
        int *data1 = NULL;
        int *data2 = NULL;
        int *data3 = NULL;

        nc_list_free(&list);
        fail_if(list, "null list returned non null after free");
        data1 = malloc(sizeof(int));
        data2 = malloc(sizeof(int));
        data3 = malloc(sizeof(int));
        fail_if(!data1 || !data2 || !data3, "malloc failed");
        fail_if(!nc_list_append(&list, data1), "Append 1 for list failed");
        fail_if(!nc_list_append(&list, data2), "Append 2 for list failed");
        fail_if(!nc_list_append(&list, data3), "Append 3 for list failed");
        nc_list_free_all(&list);
        fail_if(list, "non null list returned non null after free");
}
END_TEST

START_TEST(nc_list_check)
{
        NcList *list = NULL;
        uint i;
        char *tmp = NULL;
        char *head = "<head of the list>";
        char *head2 = "<prepend should appear before head now>";
        char *data = "<middle element to be removed>";

        /* Append 10k strings. */
        uint DEFAULT_SIZE = (10 * 1000);
        for (i = 0; i <= DEFAULT_SIZE; i++) {
                if (i == 5) {
                        fail_if(nc_list_append(&list, data) == false, "Failed to append to NcList");
                } else {
                        int j = asprintf(&tmp, "i #%d", i);
                        fail_if(j < 0, "Failed to pass test due to allocation error");
                        fail_if(nc_list_prepend(&list, tmp) == false,
                                "Failed to prepend to NcList");
                }
        }

        fail_if(list->size != DEFAULT_SIZE + 1, "List size invalid");

        /* Prepend head */
        fail_if(nc_list_prepend(&list, head) != true, "Prepend head failed");
        fail_if(list->size != DEFAULT_SIZE + 2, "Prepended head size invalid");

        /* Prepend head2 */
        fail_if(nc_list_prepend(&list, head2) != true, "Prepend head2 failed");
        fail_if(list->size != DEFAULT_SIZE + 3, "Prepended head2 size invalid");

        /* Remove from middle */
        fail_if(nc_list_remove(&list, data, false) != true, "List removal from middle failed");
        fail_if(list->size != DEFAULT_SIZE + 2, "List middle removal size invalid");

        /* Remove from end */
        fail_if(nc_list_remove(&list, tmp, true) != true, "List tail removal failed");
        fail_if(list->size != DEFAULT_SIZE + 1, "List tail removal size invalid");

        fail_if(nc_list_append(&list, "newend") != true, "List new tail append failed");
        fail_if(list->size != DEFAULT_SIZE + 2, "List new tail size invalid");
        fail_if(nc_list_remove(&list, "newend", false) != true, "List new tail removal failed");
        fail_if(list->size != DEFAULT_SIZE + 1, "List new tail size invalid (post removal)");

        /* Fake remove */
        fail_if(nc_list_remove(&list, "nonexistent", false) == true,
                "List non existent removal should fail");
        fail_if(list->size != DEFAULT_SIZE + 1, "List size invalid after no change");

        /* Remove head */
        fail_if(nc_list_remove(&list, head, false) == false, "List remove head failed");
        fail_if(nc_list_remove(&list, head2, false) == false, "List remove head2 failed");
        fail_if(list->size != DEFAULT_SIZE - 1, "List post heads removal size invalid");

        nc_list_free_all(&list);
}
END_TEST

static Suite *nc_list_suite(void)
{
        Suite *s;
        TCase *tc;

        s = suite_create("nc_list");
        tc = tcase_create("nc_list_functions");
        tcase_add_test(tc, nc_list_append_check);
        tcase_add_test(tc, nc_list_prepend_check);
        tcase_add_test(tc, nc_list_remove_check);
        tcase_add_test(tc, nc_list_foreach_check);
        tcase_add_test(tc, nc_list_free_check);
        tcase_add_test(tc, nc_list_free_all_check);
        tcase_add_test(tc, nc_list_check);
        suite_add_tcase(s, tc);

        return s;
}

int main(void)
{
        int number_failed;
        Suite *s;
        SRunner *sr;

        s = nc_list_suite();
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
