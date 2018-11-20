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

#include "os-release.h"
#include "config.h"
#include "log.h"
#include "nica/files.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * Statically defined fields for correctness of implementation
 */
static const char *os_release_fields[] = {
            [OS_RELEASE_NAME] = "NAME",
            [OS_RELEASE_VERSION] = "VERSION",
            [OS_RELEASE_ID] = "ID",
            [OS_RELEASE_VERSION_ID] = "VERSION_ID",
            [OS_RELEASE_PRETTY_NAME] = "PRETTY_NAME",
            [OS_RELEASE_ANSI_COLOR] = "ANSI_COLOR",
            [OS_RELEASE_HOME_URL] = "HOME_URL",
            [OS_RELEASE_SUPPORT_URL] = "SUPPORT_URL",
            [OS_RELEASE_BUG_REPORT_URL] = "BUG_REPORT_URL",
};

/**
 * Return a sane fallback key if one isn't provided in the config.
 */
static const char *cbm_os_release_fallback_value(CbmOsReleaseKey key)
{
        switch (key) {
        case OS_RELEASE_NAME:
                return "generic-linux-os";
        case OS_RELEASE_PRETTY_NAME:
                return "generic-linux-os";
        case OS_RELEASE_ID:
                /* Similar purpose within CBM */
                return VENDOR_PREFIX;
        case OS_RELEASE_VERSION:
        case OS_RELEASE_VERSION_ID:
                return "1";
        default:
                return "";
        }
}

/**
 * Do the actual hard work of parsing the os-release file.
 */
static bool cbm_os_release_parse(CbmOsRelease *self, const char *path)
{
        autofree(FILE) *f = NULL;
        size_t sn;
        ssize_t r = 0;
        char *buf = NULL;
        bool ret = true;

        f = fopen(path, "r");
        if (!f) {
                if (errno != ENOENT) {
                        LOG_ERROR("Unable to open %s: %s", path, strerror(errno));
                }
                return false;
        }

        while ((r = getline(&buf, &sn, f)) > 0) {
                ssize_t cur = 0;
                size_t val_len = 0;
                size_t incr = 0;
                char *key = NULL;
                autofree(char) *value = NULL;

                /* Strip newlines */
                if (r >= 1 && buf[r - 1] == '\n') {
                        buf[r - 1] = '\0';
                        --r;
                }

                char *l = buf;
                char *c = NULL;

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

                /* Look for assignment */
                c = memchr(l, '=', (size_t)r);
                if (!c) {
                        goto next_line;
                }

                /* Skip empty value */
                val_len = (size_t)(r - ((c - l) + 1));
                if (val_len < 1) {
                        goto next_line;
                }

                /* Skip empty keys */
                if (c - l < 1) {
                        goto next_line;
                }

                key = strndup(l, (size_t)(c - l));
                value = strndup(c + 1, val_len);

                /* Fix the key to always be upper case */
                char *tkey = key;
                while (*tkey != '\0') {
                        *tkey = (char)toupper(*tkey);
                        ++tkey;
                }

                if (value[val_len - 1] == '\'' || value[val_len - 1] == '\"') {
                        value[val_len - 1] = '\0';
                }

                if (value[0] == '\'' || value[0] == '\"') {
                        incr = 1;
                }

                if (!nc_hashmap_put(self, key, strdup(value + incr))) {
                        ret = false;
                        break;
                }
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

CbmOsRelease *cbm_os_release_new(const char *path)
{
        NcHashmap *ret = NULL;

        ret = nc_hashmap_new_full(nc_string_hash, nc_string_compare, free, free);
        if (!cbm_os_release_parse(ret, path)) {
                cbm_os_release_free(ret);
                return nc_hashmap_new_full(nc_string_hash, nc_string_compare, free, free);
        }

        return ret;
}

CbmOsRelease *cbm_os_release_new_for_root(const char *root)
{
        static const char *files[] = { "etc/os-release", "usr/lib/os-release" };
        CbmOsRelease *release = NULL;

        /* Loop the files until one parses, otherwise return an empty NcHashmap */
        for (size_t i = 0; i < ARRAY_SIZE(files); i++) {
                autofree(char) *p = NULL;

                p = string_printf("%s/%s", root, files[i]);

                if (!nc_file_exists(p)) {
                        continue;
                }

                release = cbm_os_release_new(p);
                if (release) {
                        return release;
                }
        }

        return nc_hashmap_new_full(nc_string_hash, nc_string_compare, free, free);
}

void cbm_os_release_free(CbmOsRelease *self)
{
        nc_hashmap_free(self);
}

const char *cbm_os_release_get_value(CbmOsRelease *self, CbmOsReleaseKey key)
{
        const char *strkey = NULL;
        const char *ret = NULL;

        /* Guard against any malloc failures */
        if (!self) {
                return cbm_os_release_fallback_value(key);
        }

        if (key <= OS_RELEASE_MIN || key >= OS_RELEASE_MAX) {
                return NULL;
        }

        strkey = os_release_fields[key];
        ret = nc_hashmap_get(self, strkey);
        if (!ret) {
                ret = cbm_os_release_fallback_value(key);
        }

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
