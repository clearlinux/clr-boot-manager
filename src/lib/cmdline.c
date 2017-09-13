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

/**
 * Attempt to parse the command line file and add it to the given output file.
 *
 * @Returns negative code if parsing failed, otherwise the number of bytes (>0)
 */
static int cbm_parse_cmdline_file_internal(const char *path, FILE *out)
{
        autofree(FILE) *f = NULL;
        size_t sn;
        ssize_t r = 0;
        char *buf = NULL;
        bool ret = true;
        bool hadcontent = false;
        int nbytes = 0;

        f = fopen(path, "r");
        if (!f) {
                if (errno != ENOENT) {
                        LOG_ERROR("Unable to open %s: %s", path, strerror(errno));
                }
                return false;
        }

        while ((r = getline(&buf, &sn, f)) > 0) {
                ssize_t cur = 0;

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
                        ++nbytes;
                }

                if (fwrite(l, (size_t)r, 1, out) != 1) {
                        ret = false;
                        break;
                }
                nbytes += (int)r;

                hadcontent = true;
        next_line:
                free(buf);
                buf = NULL;
        }

        if (buf) {
                free(buf);
                buf = NULL;
        }

        if (!ret) {
                return -1;
        }
        return nbytes;
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
        if (cbm_parse_cmdline_file_internal(file, memstr) < 0) {
                fclose(memstr);
                return NULL;
        }
        fclose(memstr);
        return strdup(buf);
}

/**
 * Determine if there is a version of this file within the /etc/ tree that
 * is "masking" the vendor file (i.e. it has the same name)
 */
static bool cbm_cmdline_disabled_by_mask(const char *root, char *path)
{
        autofree(char) *cmp = NULL;
        autofree(char) *alt_path = NULL;
        char *bcp = NULL;

        cmp = strdup(path);
        if (!cmp) {
                return false;
        }
        bcp = basename(cmp);
        if (!bcp) {
                return false;
        }

        /* Find this path within /etc/ tree */
        alt_path = string_printf("%s/%s/cmdline.d/%s", root, KERNEL_CONF_DIRECTORY, bcp);
        return nc_file_exists(alt_path);
}

/**
 * Determine if the file is disabled through a link to /dev/null and should be
 * ignored. Together with @cbm_cmdline_disabled_by_mask, it is possible to disable
 * a vendor file by masking the file into /etc/kernel/cmdline.d and linking it to
 * /dev/null.
 */
static bool cbm_cmdline_disabled_by_link(char *path)
{
        autofree(char) *p = NULL;

        /* GCC incorrectly complains about us freeing the return from realpath()
         * which is allocated, however GCC believes it is heap storage.
         */
        p = realpath(path, NULL);
        if (!p) {
                return false;
        }
        return streq(p, "/dev/null");
}

/**
 * Glob *.conf files within the given glob, and merge the resulting command
 * line into the final stream
 *
 * @Returns negative code if the call failed, or the number of files processed.
 */
static int cbm_parse_cmdline_files_directory(const char *root, bool bump_start, bool check_masked,
                                             char *globfile, FILE *memstr)
{
        glob_t glo = { 0 };
        glo.gl_offs = 0;
        glob(globfile, GLOB_DOOFFS, NULL, &glo);
        int ret = -1;
        size_t true_index = 0;

        for (size_t i = 0; i < glo.gl_pathc; i++) {
                char *argv = glo.gl_pathv[i];
                int r = 0;

                /* If we're in a maskable directory, check if it's masked. */
                if (check_masked && cbm_cmdline_disabled_by_mask(root, argv)) {
                        LOG_DEBUG("Skipping masked file: %s", argv);
                        continue;
                }

                /* If we're not in a maskable, check if it links to /dev/null */
                if (!check_masked && cbm_cmdline_disabled_by_link(argv)) {
                        LOG_DEBUG("Skipping disabled cmdline: %s", argv);
                        continue;
                }

                if (true_index > 0 || bump_start) {
                        /* add a space between all files, after the first file. */
                        if (fwrite(" ", 1, 1, memstr) != 1) {
                                goto clean;
                        }
                        if (bump_start) {
                                bump_start = false;
                        }
                }

                r = cbm_parse_cmdline_file_internal(argv, memstr);
                if (r < 0) {
                        goto clean;
                } else if (r > 0) {
                        /* Prevent accidental spaces for masked or empty files */
                        ++true_index;
                }
        }

        // 0 or more
        ret = (int)true_index;

clean:
        globfree(&glo);
        return ret;
}

char *cbm_parse_cmdline_files(const char *root)
{
        autofree(char) *cmdline = NULL;
        autofree(char) *globfile = NULL;
        autofree(char) *vendor_glob = NULL;
        FILE *memstr = NULL;
        autofree(char) *buf = NULL;
        bool bump_start = false;
        int ret = 0;
        size_t sz = 0;

        bool fail = true;

        /* global cmdline */
        cmdline = string_printf("%s/%s/cmdline", root, KERNEL_CONF_DIRECTORY);
        globfile = string_printf("%s/%s/cmdline.d/*.conf", root, KERNEL_CONF_DIRECTORY);
        vendor_glob = string_printf("%s/%s/cmdline.d/*.conf", root, VENDOR_KERNEL_CONF_DIRECTORY);

        memstr = open_memstream(&buf, &sz);
        if (!memstr) {
                return NULL;
        }

        /* Merge vendor cmdline.d files if present */
        ret = cbm_parse_cmdline_files_directory(root, bump_start, true, vendor_glob, memstr);
        bump_start = ret >= 1;
        if (ret < 0) {
                goto clean;
        }

        /* If the local system cmdline exists, merge it it */
        if (nc_file_exists(cmdline)) {
                /* Add a space after the vendor files */
                if (bump_start && fwrite(" ", 1, 1, memstr) != 1) {
                        goto clean;
                }
                ret = cbm_parse_cmdline_file_internal(cmdline, memstr);
                if (ret < 0) {
                        goto clean;
                } else if (ret > 0) {
                        /* Might not have had vendor files */
                        bump_start = true;
                }
        }

        /* Merge system cmdline.d files if present */
        if (cbm_parse_cmdline_files_directory(root, bump_start, false, globfile, memstr) < 0) {
                goto clean;
        }

        fail = false;
clean:
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
