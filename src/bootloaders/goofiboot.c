/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2016-2017 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE

#include "systemd-class.h"

static BootLoaderConfig goofiboot_config = {.vendor_dir = "goofiboot",
                                            .efi_dir = "/usr/lib/goofiboot",
                                            .efi_blob = "goofiboot" SYSTEMD_EFI_SUFFIX,
                                            .name = "goofiboot" };

static bool goofiboot_init(const BootManager *manager)
{
        return sd_class_init(manager, &goofiboot_config);
}

__cbm_export__ const BootLoader
    goofiboot_bootloader = {.name = "goofiboot",
                            .init = goofiboot_init,
                            .get_kernel_destination = sd_class_get_kernel_destination,
                            .install_kernel = sd_class_install_kernel,
                            .remove_kernel = sd_class_remove_kernel,
                            .set_default_kernel = sd_class_set_default_kernel,
                            .needs_install = sd_class_needs_install,
                            .needs_update = sd_class_needs_update,
                            .install = sd_class_install,
                            .update = sd_class_update,
                            .remove = sd_class_remove,
                            .destroy = sd_class_destroy,
                            .get_capabilities = sd_class_get_capabilities };

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
