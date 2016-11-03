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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "files.h"
#include "util.h"

#define COPY_BUFFER_SIZE 8192

DEF_AUTOFREE(DIR, closedir)

bool nc_file_exists(const char *path)
{
        struct stat st = {.st_ino = 0 };
        return (lstat(path, &st) == 0);
}

char *nc_get_file_parent(const char *path)
{
        autofree(char) *d = strdup(path);
        char *r = realpath(dirname(d), NULL);
        return r;
}

bool nc_mkdir_p(const char *path, mode_t mode)
{
        autofree(char) *cl = NULL;
        char *cl_base = NULL;

        if (streq(path, ".") || streq(path, "/") || streq(path, "//")) {
                return true;
        }

        cl = strdup(path);
        cl_base = dirname(cl);

        if (!nc_mkdir_p(cl_base, mode) && errno != EEXIST) {
                return false;
        }

        return !((mkdir(path, mode) < 0 && errno != EEXIST));
}

/**
 * nftw callback
 */
static int _rm_rf(const char *path, __attribute__((unused)) const struct stat *sb, int typeflag,
                  __attribute__((unused)) struct FTW *ftwbuf)
{
        switch (typeflag) {
        case FTW_F:
        case FTW_SL:
        case FTW_SLN:
                return unlink(path);
        default:
                return rmdir(path);
        }
}

bool nc_rm_rf(const char *path)
{
        bool ret = nftw(path, _rm_rf, 35, FTW_DEPTH) == 0;

        return ret;
}

bool nc_copy_file(const char *src, const char *dst, mode_t mode, bool remove_target)
{
        int src_fd = -1;
        int dest_fd = -1;
        bool ret = true;
        char buffer[COPY_BUFFER_SIZE] = { 0 };
        ssize_t r = 0;

        if (remove_target) {
                if (nc_file_exists(dst) && unlink(dst) < 0) {
                        return false;
                }
                sync();
        }

        src_fd = open(src, O_RDONLY);
        if (src_fd < 0) {
                return false;
        }

        dest_fd = open(dst, O_WRONLY | O_TRUNC | O_APPEND | O_CREAT, mode);
        if (dest_fd < 0) {
                ret = false;
                goto end;
        }

        while (true) {
                if ((r = read(src_fd, &buffer, sizeof(buffer))) < 0) {
                        ret = false;
                        goto end;
                }
                if (write(dest_fd, buffer, sizeof(buffer)) != r) {
                        break;
                }
        }

        ret = true;
end:
        if (src_fd >= 0) {
                close(src_fd);
        }
        if (dest_fd >= 0) {
                close(dest_fd);
        }
        if (remove_target) {
                sync();
        }

        return ret;
}

/*
 * The following functions are taken from Ikey Doherty's goofiboot
 * project
 */
char *nc_build_case_correct_path_va(const char *c, va_list ap)
{
        char *p = NULL;
        char *root = NULL;
        struct stat st = {.st_ino = 0 };
        struct dirent *ent = NULL;

        p = (char *)c;

        while (p) {
                char *t = NULL;
                char *sav = NULL;
                autofree(DIR) *dirn = NULL;

                if (!root) {
                        root = strdup(p);
                } else {
                        sav = strdup(root);

                        if (asprintf(&t, "%s/%s", root, p) < 0) {
                                fprintf(stderr,
                                        "nc_build_case_correct_path_va: Out "
                                        "of memory\n");
                                va_end(ap);
                                if (sav) {
                                        free(sav);
                                }
                                return NULL;
                        }
                        free(root);
                        root = t;
                        t = NULL;
                }

                autofree(char) *dirp = strdup(root);
                char *dir = dirname(dirp);

                if (stat(dir, &st) != 0) {
                        goto clean;
                }
                if (!S_ISDIR(st.st_mode)) {
                        goto clean;
                }
                /* Iterate the directory and find the case insensitive name,
                 * using
                 * this if it exists. Otherwise continue with the non existent
                 * path
                 */
                dirn = opendir(dir);
                if (!dirn) {
                        goto clean;
                }
                while ((ent = readdir(dirn)) != NULL) {
                        if (strncmp(ent->d_name, ".", 1) == 0 ||
                            strncmp(ent->d_name, "..", 2) == 0) {
                                continue;
                        }
                        if (strcasecmp(ent->d_name, p) == 0) {
                                if (sav) {
                                        if (asprintf(&t, "%s/%s", sav, ent->d_name) < 0) {
                                                fprintf(stderr,
                                                        "nc_build_case_"
                                                        "correct_path_va: Out "
                                                        "of memory\n");
                                                return NULL;
                                        }
                                        free(root);
                                        root = t;
                                        t = NULL;
                                } else {
                                        if (root) {
                                                sav = strdup(root);
                                                free(root);
                                                root = NULL;
                                                if (!sav) {
                                                        fprintf(stderr,
                                                                "nc_build_"
                                                                "case_correct_"
                                                                "path_va: Out "
                                                                "of memory\n");
                                                        return NULL;
                                                }
                                        }
                                }
                                break;
                        }
                }
        clean:
                if (sav) {
                        free(sav);
                }
                p = va_arg(ap, char *);
        }

        return root;
}

char *nc_build_case_correct_path(const char *c, ...)
{
        va_list ap;

        char *ret = NULL;
        va_start(ap, c);
        ret = nc_build_case_correct_path_va(c, ap);
        va_end(ap);

        return ret;
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
