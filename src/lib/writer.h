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

#pragma once

#include "nica/util.h"

#define _GNU_SOURCE

typedef struct CbmWriter {
        FILE *memstream;
        char *buffer;
        size_t buffer_n;
        int error;
} CbmWriter;

#define CBM_WRITER_INIT &(CbmWriter){ 0 };

/**
 * Construct a new CbmWriter
 */
bool cbm_writer_open(CbmWriter *writer);

/**
 * Clean up a previously allocated CbmWriter
 */
void cbm_writer_free(CbmWriter *writer);

/**
 * Close the writer, which will ensure that the buffer is NULL terminated.
 * No more writes are possible after this close.
 */
void cbm_writer_close(CbmWriter *writer);

/**
 * Append string to the buffer
 */
void cbm_writer_append(CbmWriter *writer, const char *s);

/**
 * Append, printf style, to the buffer
 */
void cbm_writer_append_printf(CbmWriter *writer, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/**
 * Return an error that may exist in the stream, otherwise 0.
 * This allows utilising CbmWriter in a failsafe fashion, and checking the
 * error once only.
 */
int cbm_writer_error(CbmWriter *writer);

/* Convenience: Automatically clean up the CbmWriter */
DEF_AUTOFREE(CbmWriter, cbm_writer_free)

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
