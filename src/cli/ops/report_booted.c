/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2016-2018 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "bootman.h"
#include "cli.h"
#include "config.h"
#include "files.h"
#include "nica/files.h"
#include "nica/util.h"
#include "report_booted.h"

bool cbm_command_report_booted(__cbm_unused__ int argc, __cbm_unused__ char **argv)
{
        SystemKernel sys = { 0 };
        struct utsname uts = { 0 };
        const char *lib_dir = "/var/lib/kernel";
        autofree(char) *boot_rep_path = NULL;

        /* Try to parse the currently running kernel */
        if (uname(&uts) < 0) {
                fprintf(stderr, "uname() broken: %s\n", strerror(errno));
                return false;
        }

        if (!cbm_parse_system_kernel(uts.release, &sys)) {
                fprintf(stderr, "Booting with unknown kernel: %s\n", uts.release);
                return false;
        }

        /* Disable syncs during boot ! */
        cbm_set_sync_filesystems(false);

        if (!nc_file_exists(lib_dir)) {
                if (!nc_mkdir_p(lib_dir, 00755)) {
                        fprintf(stderr, "Unable to mkdir_p: %s %s\n", lib_dir, strerror(errno));
                        return false;
                }
        }

        /* /var/lib/kernel/k_booted_4.4.0-120.lts - new */
        boot_rep_path =
            string_printf("/var/lib/kernel/k_booted_%s-%d.%s", sys.version, sys.release, sys.ktype);

        /* Report ourselves to new path */
        if (!file_set_text(boot_rep_path, "clr-boot-manager file\n")) {
                fprintf(stderr, "Failed to set kernel boot status: %s\n", strerror(errno));
                return false;
        }

        /* Done */
        return true;
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
