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

static BootLoaderConfig gummiboot_config = {.vendor_dir = "gummiboot",
                                            .efi_dir = "/usr/lib/gummiboot",
                                            .x64_blob = "gummibootx64.efi",
                                            .ia32_blob = "gummibootia32.efi",
                                            .name = "gummiboot" };

static bool gummiboot_init(const BootManager *manager)
{
        return sd_class_init(manager, &gummiboot_config);
}

__cbm_export__ const BootLoader gummiboot_bootloader = {.name = "gummiboot",
                                                        .init = gummiboot_init,
                                                        .install_kernel = sd_class_install_kernel,
                                                        .remove_kernel = sd_class_remove_kernel,
                                                        .set_default_kernel =
                                                            sd_class_set_default_kernel,
                                                        .needs_install = sd_class_needs_install,
                                                        .needs_update = sd_class_needs_update,
                                                        .install = sd_class_install,
                                                        .update = sd_class_update,
                                                        .remove = sd_class_remove,
                                                        .destroy = sd_class_destroy };

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
