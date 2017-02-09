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

#pragma once

#include <stdbool.h>
#include <stdlib.h>

#include "bootman.h"

/**
 * Needed for intiialisation
 */
typedef struct PlaygroundKernel {
        const char *version;
        const char *ktype;
        int release;
        bool default_for_type;
} PlaygroundKernel;

/**
 * Playground initialisation
 */
typedef struct PlaygroundConfig {
        const char *uts_name;
        PlaygroundKernel *initial_kernels;
        size_t n_kernels;
        bool uefi;
} PlaygroundConfig;

/**
 * Return a new BootManager for the newly prepared playground.
 * Will return null if initialisation failed
 */
BootManager *prepare_playground(PlaygroundConfig *config);

/**
 * Push a new kernel into the root
 */
bool push_kernel_update(PlaygroundKernel *kernel);

/**
 * Set the current kernel as the default for it's type, overriding any
 * previous configuration.
 */
bool set_kernel_default(PlaygroundKernel *kernel);

/**
 * Mark the kernel as having booted
 */
bool set_kernel_booted(PlaygroundKernel *kernel, bool did_boot);

/**
 * Push a faux-bootloader with the content specified by @version.
 * This enables testing bootloader operations without requiring
 * the real files, as well as testing update behaviour for source
 * changes.
 *
 * @note The default revision is 0, so to push a faux update, make sure to
 * use a higher revision number.
 */
bool push_bootloader_update(int revision);

/**
 * Util - confirm the bootloader is installed in the current test
 */
void confirm_bootloader(void);

/**
 * Util - confirm the bootloader installed matches the source file
 */
bool confirm_bootloader_match(void);

/**
 * Assert that the kernel is fully installed
 */
bool confirm_kernel_installed(BootManager *manager, PlaygroundKernel *kernel);

/**
 * Assert that the kernel is fully uninstalled
 */
bool confirm_kernel_uninstalled(BootManager *manager, PlaygroundKernel *kernel);

/**
 * Create boot_timeout.conf in /etc
 */
bool create_timeout_conf(void);

/**
 * Set up the test harness to emulate UEFI
 */
void set_test_system_uefi(void);

/**
 * Set up the test harness to emulate legacy boot
 */
void set_test_system_legacy(void);

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
