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

#include "cmdline.h"
#include "config.h"
#include "files.h"
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
                l = rstrip(l, (size_t *)&r);

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

/**
 * Attempt to parse a command line file and remove its content from the out buffer.
 *
 * @Returns negative code if parsing failed, otherwise the new buffer size.
 */
static int cbm_parse_cmdline_file_removal_internal(const char *path, char *out, size_t buflen)
{
        autofree(FILE) *f = NULL;
        size_t sn = 0;
        ssize_t r = 0;
        size_t sz = 0;
        char *buf = NULL;
        size_t nbytes = buflen;

        /* Cleanup trailing whitespace of out buf */
        out = rstrip(out, &nbytes);

        f = fopen(path, "r");
        if (!f) {
                if (errno != ENOENT) {
                        LOG_ERROR("Unable to open %s: %s", path, strerror(errno));
                }
                return -1;
        }

        while ((r = getline(&buf, &sn, f)) > 0) {
                sz = (size_t)r;
                char *m = NULL;

                /* Strip newlines */
                if (sz >= 1 && buf[sz - 1] == '\n') {
                        buf[sz - 1] = '\0';
                        --sz;
                }
                char *l = buf;

                /* Skip empty lines */
                if (sz < 1) {
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
                sz = sz - (size_t)(l - buf);

                /* Strip trailing whitespace */
                l = rstrip(l, &sz);

                /* May now be an empty line */
                if (sz < 1) {
                        goto next_line;
                }

                m = memmem(out, nbytes, l, sz);
                if (!m) {
                        goto next_line;
                }

                /* check match wasn't a substring */
                if (m[sz] != '\0' && m[sz] != ' ') {
                        goto next_line;
                }

                /* Given memem matched, check if it matched the entire line */
                if (sz == nbytes) {
                        m[0] = '\0';
                } else {
                        /* Kill spaces in between options */
                        if (m[sz] == ' ') {
                                sz += 1;
                        }

                        /* a bit of casting but given memem results we assume:
                           out <= m && nbytes > sz
                           this means m - out is the distance from the start
                           of the string to the start of the match and
                           nbytes - sz is the length of the characters not
                           in the match
                           this leaves rest_len to be the number of characters
                           that were not in the match minus the characters
                           before the match as the number of characters needed
                           to be copied */

                        /* Example:
                           out = "test cmdline options"
                           m = "cmdline options"
                           sz = 8 -> strlen("cmdline ")
                           nbytes = 20 -> strlen("test cmdline options")
                           nbytes - sz = 12 -> strlen("test ")
                           + strlen("options")
                           m - out = 5 -> 0x5 - 0x0
                           12 - 5 = 7 -> strlen("options") == rest_len
                           0x5 + 8 = 13 -> out[13] = 'o'
                           (next character position in out after m) */
                        size_t rest_len = (nbytes - sz) - (size_t)(m - out);
                        (void)memmove(m, m + sz, rest_len);
                        m[rest_len] = '\0';
                }
                nbytes -= sz;

        next_line:
                free(buf);
                buf = NULL;
        }

        if (buf) {
                free(buf);
                buf = NULL;
        }

        return (int)nbytes;
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
                if (!check_masked && cbm_path_check(argv, "/dev/null")) {
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

void cbm_parse_cmdline_removal_files_directory(const char *root, char *buffer)
{
        glob_t glo = { 0 };
        autofree(char) *globfile = NULL;

        glo.gl_offs = 0;
        size_t sz = strlen(buffer);
        globfile = string_printf("%s/%s/cmdline-removal.d/*.conf", root, KERNEL_CONF_DIRECTORY);
        glob(globfile, GLOB_DOOFFS, NULL, &glo);

        for (size_t i = 0; i < glo.gl_pathc; i++) {
                char *argv = glo.gl_pathv[i];
                int r = 0;

                LOG_DEBUG("Removing cmdline using file: %s", argv);
                r = cbm_parse_cmdline_file_removal_internal(argv, buffer, sz);
                if (r < 0) {
                        continue;
                }
                sz = (size_t)r;
        }

        globfree(&glo);
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

        bool success = false;

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
        success = true;

clean:
        fclose(memstr);
        if (success) {
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
