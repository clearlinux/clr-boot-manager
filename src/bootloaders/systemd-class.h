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

#include "bootloader.h"
#include "bootman.h"

#pragma once

#if UINTPTR_MAX == 0xffffffffffffffff
#define SYSTEMD_EFI_SUFFIX "x64.efi"
#else
#define SYSTEMD_EFI_SUFFIX "ia32.efi"
#endif

typedef struct BootLoaderConfig {
        const char *vendor_dir;
        const char *efi_dir;
        const char *efi_blob;
        const char *name;
} BootLoaderConfig;

bool sd_class_install_kernel(const BootManager *manager, const Kernel *kernel);

bool sd_class_remove_kernel(const BootManager *manager, const Kernel *kernel);

bool sd_class_set_default_kernel(const BootManager *manager, const Kernel *kernel);

bool sd_class_needs_install(const BootManager *manager);

bool sd_class_needs_update(const BootManager *manager);

bool sd_class_install(const BootManager *manager);

bool sd_class_update(const BootManager *manager);

bool sd_class_remove(const BootManager *manager);

bool sd_class_init(const BootManager *manager, BootLoaderConfig *config);

void sd_class_destroy(const BootManager *manager);

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
