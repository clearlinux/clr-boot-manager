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
#include <check.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "bootman.h"
#include "config.h"
#include "files.h"
#include "log.h"
#include "nica/array.h"
#include "nica/files.h"
#include "util.h"
#include "writer.h"

#include "blkid-harness.h"
#include "harness.h"
#include "system-harness.h"

#define PLAYGROUND_ROOT TOP_BUILD_DIR "/tests/update_playground"

static PlaygroundKernel uefi_kernels[] = { { "4.2.1", "kvm", 121, false },
                                           { "4.2.3", "kvm", 124, true },
                                           { "4.2.1", "native", 137, false },
                                           { "4.2.3", "native", 138, true } };

static PlaygroundConfig uefi_config = { "4.2.1-121.kvm",
                                        uefi_kernels,
                                        ARRAY_SIZE(uefi_kernels),
                                        .uefi = true };

#define PLAYGROUND_ROOT TOP_BUILD_DIR "/tests/update_playground"

START_TEST(bootman_uefi_get_boot_device)
{
        autofree(char) *boot_device = NULL;
        autofree(BootManager) *m = NULL;
        autofree(char) *exp = NULL;

        /* Ensure cleanup */
        m = prepare_playground(&uefi_config);

        boot_device = get_legacy_boot_device(PLAYGROUND_ROOT);
        fail_if(boot_device != NULL, "Found incorrect legacy device for UEFI Boot");

        boot_device = get_boot_device();
        fail_if(!boot_device, "Failed to determine UEFI boot device");

        if (asprintf(&exp,
                     "%s/dev/disk/by-partuuid/e90f44b5-bb8a-41af-b680-b0bf5b0f2a65",
                     PLAYGROUND_ROOT) < 0) {
                abort();
        }
        fail_if(!streq(exp, boot_device), "Boot device does not match expected result");
}
END_TEST

START_TEST(bootman_uefi_image)
{
        autofree(BootManager) *m = NULL;
        m = prepare_playground(&uefi_config);
        fail_if(!m, "Failed to prepare update playground");

        /* Validate image install */
        boot_manager_set_image_mode(m, true);
        fail_if(!boot_manager_update(m), "Failed to update image");
}
END_TEST

static Suite *core_suite(void)
{
        Suite *s = NULL;
        TCase *tc = NULL;

        s = suite_create("bootman_uefi");
        tc = tcase_create("bootman_uefi_functions");
        tcase_add_test(tc, bootman_uefi_get_boot_device);
        tcase_add_test(tc, bootman_uefi_image);
        suite_add_tcase(s, tc);

        return s;
}

int main(void)
{
        Suite *s;
        SRunner *sr;
        int fail;

        /* syncing can be problematic during test suite runs */
        cbm_set_sync_filesystems(false);

        /* Ensure that logging is set up properly. */
        setenv("CBM_DEBUG", "1", 1);
        cbm_log_init(stderr);

        cbm_blkid_set_vtable(&BlkidTestOps);
        cbm_system_set_vtable(&SystemTestOps);

        s = core_suite();
        sr = srunner_create(s);
        srunner_run_all(sr, CK_VERBOSE);
        fail = srunner_ntests_failed(sr);
        srunner_free(sr);

        if (fail > 0) {
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
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
