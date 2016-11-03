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

#pragma once

#include "macros.h"
#include <search.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * A dynamic array
 */
typedef struct NcArray {
        void **data;  /**<Dynamic array contents */
        uint16_t len; /**<Length of the array */
} NcArray;

/**
 * Valid function prototype for 'free' method
 * @param p Pointer to free
 */
typedef void (*array_free_func)(void *p);

/**
 * Create a new NcArray
 * @returns NcArray a newly allocated NcArray
 */
_nica_public_ NcArray *nc_array_new(void) __attribute__((warn_unused_result));

/**
 * Append data to NcArray
 * @param array Valid NcArray
 * @param data Pointer to add to this array
 * @returns bool true if the data was added to the array
 */
_nica_public_ bool nc_array_add(NcArray *array, void *data) __attribute__((warn_unused_result));

/**
 * Free an array, and optionally its members
 * @param array valid NcArray reference
 * @param free_func Function to call to free all members, or NULL to leave
 * allocated
 */
_nica_public_ void nc_array_free(NcArray **array, array_free_func free_method);

/**
 * Retrieve an element from the array by index
 * @param array valid NcArray reference
 * @param index index of the element in the array
 * @return a data pointer referred to by index, or NULL
 */
_nica_public_ void *nc_array_get(NcArray *array, uint16_t index)
    __attribute__((warn_unused_result));

/**
 * Sort the internal array using the qsort() function
 *
 * @param array valid NcArray reference
 * @param cmp a comparison_fn_t pointer
 */
_nica_public_ void nc_array_qsort(NcArray *array, __compar_fn_t cmp);

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
