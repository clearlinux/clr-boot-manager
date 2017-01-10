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

#define _GNU_SOURCE

#include "cmdline.h"
#include "config.h"
#include "log.h"
#include "nica/files.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>

static bool cbm_parse_cmdline_file_internal(const char *path, FILE *out)
{
        autofree(FILE) *f = NULL;
        size_t sn;
        ssize_t r = 0;
        char *buf = NULL;
        bool ret = true;
        bool hadcontent = false;

        f = fopen(path, "r");
        if (!f) {
                if (errno != ENOENT) {
                        LOG_ERROR("Unable to open %s: %s", path, strerror(errno));
                }
                return false;
        }

        while ((r = getline(&buf, &sn, f)) > 0) {
                ssize_t cur = 0;
                autofree(char) *value = NULL;

                /* Strip newlines */
                if (r >= 1 && buf[r - 1] == '\n') {
                        buf[r - 1] = '\0';
                        --r;
                }
                char *l = buf;

                /* Skip empty lines */
                if (r < 1) {
                        goto next_line;
                }

                /* Skip the starting whitespace */
                while (isspace(*l)) {
                        ++l;
                        if (!*l) {
                                break;
                        }
                }

                /* Skip a comment */
                if (l[0] == '#') {
                        goto next_line;
                }

                /* Reset length */
                cur = (l - buf);
                r -= cur;

                /* Strip trailing whitespace */
                l = rstrip(l, (size_t)r, &r);

                /* May now be an empty line */
                if (r < 1) {
                        goto next_line;
                }

                /* For successive new lines, add a space before writing anything. */
                if (hadcontent) {
                        if (fwrite(" ", 1, 1, out) != 1) {
                                ret = false;
                                break;
                        }
                }

                if (fwrite(l, (size_t)r, 1, out) != 1) {
                        ret = false;
                        break;
                }
                hadcontent = true;
        next_line:
                free(buf);
                buf = NULL;
        }

        if (buf) {
                free(buf);
                buf = NULL;
        }
        return ret;
}

char *cbm_parse_cmdline_file(const char *file)
{
        FILE *memstr = NULL;
        autofree(char) *buf = NULL;
        size_t sz = 0;

        memstr = open_memstream(&buf, &sz);
        if (!memstr) {
                return NULL;
        }
        if (!cbm_parse_cmdline_file_internal(file, memstr)) {
                fclose(memstr);
                return NULL;
        }
        fclose(memstr);
        return strdup(buf);
}

char *cbm_parse_cmdline_files(const char *root)
{
        autofree(char) *cmdline = NULL;
        autofree(char) *globfile = NULL;
        FILE *memstr = NULL;
        autofree(char) *buf = NULL;
        size_t sz = 0;
        glob_t glo = { 0 };
        bool fail = true;
        size_t arg_start = 0;

        /* global cmdline */
        if (asprintf(&cmdline, "%s/%s/cmdline", root, KERNEL_CONF_DIRECTORY) < 0) {
                DECLARE_OOM();
                return false;
        }

        /* glob match */
        if (asprintf(&globfile, "%s/%s/cmdline.d/*.conf", root, KERNEL_CONF_DIRECTORY) < 0) {
                DECLARE_OOM();
                return false;
        }

        memstr = open_memstream(&buf, &sz);
        if (!memstr) {
                return NULL;
        }

        glo.gl_offs = 1;
        glob(globfile, GLOB_DOOFFS, NULL, &glo);
        glo.gl_pathv[0] = cmdline;
        arg_start = 0;
        /* Don't parse etc/kernel/cmdline if it's not there */
        if (!nc_file_exists(cmdline)) {
                arg_start += 1;
        }

        for (size_t i = arg_start; i < glo.gl_pathc + 1; i++) {
                if (arg_start - i > 0) {
                        /* add a space between all files, after the first file. */
                        if (fwrite(" ", 1, 1, memstr) != 1) {
                                goto clean;
                        }
                }
                if (!cbm_parse_cmdline_file_internal(glo.gl_pathv[i], memstr)) {
                        goto clean;
                }
        }
        fail = false;
clean:
        globfree(&glo);
        fclose(memstr);
        if (!fail) {
                return strdup(buf);
        }
        return NULL;
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
