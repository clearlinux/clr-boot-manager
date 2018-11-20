/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2017-2018 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE

#include "writer.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

bool cbm_writer_open(CbmWriter *writer)
{
        if (!writer) {
                return false;
        }

        if (writer->buffer || writer->memstream) {
                return false;
        }

        writer->memstream = open_memstream(&writer->buffer, &writer->buffer_n);
        if (!writer->memstream) {
                writer->error = ENOMEM;
                return false;
        }

        return true;
}

void cbm_writer_free(CbmWriter *self)
{
        if (!self) {
                return;
        }
        cbm_writer_close(self);
        free(self->buffer);
}

void cbm_writer_close(CbmWriter *self)
{
        if (!self) {
                return;
        }
        if (!self->memstream) {
                return;
        }
        fclose(self->memstream);
        self->memstream = NULL;
}

void cbm_writer_append(CbmWriter *self, const char *s)
{
        if (!self || self->error != 0) {
                return;
        }

        /* Set EBADF as we tried to use a closed memstream */
        if (!self->memstream) {
                self->error = EBADF;
                return;
        }

        if (fprintf(self->memstream, "%s", s) < 0) {
                self->error = errno;
        }
}

void cbm_writer_append_printf(CbmWriter *self, const char *fmt, ...)
{
        if (!self || self->error != 0) {
                return;
        }

        /* Set EBADF as we tried to use a closed memstream */
        if (!self->memstream) {
                self->error = EBADF;
                return;
        }

        va_list va;

        va_start(va, fmt);
        if (vfprintf(self->memstream, fmt, va) < 0) {
                self->error = errno;
        }
        va_end(va);
}

int cbm_writer_error(CbmWriter *self)
{
        if (self) {
                return self->error;
        }
        /* Assume enomem with pointer issues */
        return ENOMEM;
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
