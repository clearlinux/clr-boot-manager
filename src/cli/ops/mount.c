/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2016-2018 Intel Corporation
 * Copyright © 2020 Silke Hofstra
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include "bootman.h"
#include "cli.h"
#include "log.h"

bool cbm_command_mount_boot(int argc, char **argv)
{
        autofree(char) *root = NULL;
        autofree(BootManager) *manager = NULL;
        bool forced_image = false;
        bool update_efi_vars = false;
        autofree(char) *boot_dir = NULL;
        int did_mount = -1;

        if (!cli_default_args_init(&argc, &argv, &root, &forced_image, &update_efi_vars)) {
                return false;
        }

        manager = boot_manager_new();
        if (!manager) {
                DECLARE_OOM();
                return false;
        }

        boot_manager_set_update_efi_vars(manager, update_efi_vars);

        if (root) {
                autofree(char) *realp = NULL;

                realp = realpath(root, NULL);
                if (!realp) {
                        LOG_FATAL("Path specified does not exist: %s", root);
                        return false;
                }
                /* Anything not / is image mode */
                if (!streq(realp, "/")) {
                        boot_manager_set_image_mode(manager, true);
                } else {
                        boot_manager_set_image_mode(manager, forced_image);
                }

                /* CBM will check this again, we just needed to check for
                 * image mode.. */
                if (!boot_manager_set_prefix(manager, root)) {
                        return false;
                }
        } else {
                boot_manager_set_image_mode(manager, forced_image);
                /* Default to "/", bail if it doesn't work. */
                if (!boot_manager_set_prefix(manager, "/")) {
                        return false;
                }
        }

        /* Let CBM detect and mount the boot directory */
        did_mount = boot_manager_detect_and_mount_boot(manager, &boot_dir);
        return did_mount >= 0;
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
