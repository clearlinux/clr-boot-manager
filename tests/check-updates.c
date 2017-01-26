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

#include <assert.h>
#include <check.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bootman.h"
#include "files.h"
#include "log.h"
#include "nica/files.h"

#include "blkid-harness.h"
#include "config.h"
#include "harness.h"

START_TEST(bootman_image_test_simple)
{
        autofree(BootManager) *m = NULL;

        PlaygroundKernel init_kernels[] = {
                { "4.6.0", "native", 180, true },
                { "4.4.4", "native", 160, false },
                { "4.4.0", "native", 140, false },
        };
        PlaygroundConfig start_conf = { NULL, init_kernels, ARRAY_SIZE(init_kernels) };

        m = prepare_playground(&start_conf);
        fail_if(!m, "Fatal: Cannot initialise playground");
        boot_manager_set_image_mode(m, true);

        fail_if(!boot_manager_update(m), "Failed to update in image mode");

        confirm_bootloader();
}
END_TEST

/**
 * Identical to bootman_image_test_simple, but in native mode
 */
START_TEST(bootman_native_test_simple)
{
        autofree(BootManager) *m = NULL;

        PlaygroundKernel init_kernels[] = {
                { "4.6.0", "native", 180, true },
                { "4.4.4", "native", 160, false },
                { "4.4.0", "native", 140, false },
        };
        PlaygroundConfig start_conf = { "4.4.4-160.native",
                                        init_kernels,
                                        ARRAY_SIZE(init_kernels) };

        m = prepare_playground(&start_conf);
        fail_if(!m, "Fatal: Cannot initialise playground");
        boot_manager_set_image_mode(m, false);
        fail_if(!set_kernel_booted(&init_kernels[1], true), "Failed to set kernel as booted");

        fail_if(!boot_manager_update(m), "Failed to update in native mode");

        /* Latest kernel for us */
        fail_if(!confirm_kernel_installed(m, &(init_kernels[0])), "Newest kernel not installed");

        /* Running kernel */
        fail_if(!confirm_kernel_installed(m, &(init_kernels[1])), "Newest kernel not installed");

        /* This guy isn't supposed to be kept around now */
        fail_if(!confirm_kernel_uninstalled(m, &(init_kernels[2])),
                "Uninteresting kernel shouldn't be kept around.");

        confirm_bootloader();
}
END_TEST

static void internal_loader_test(bool image_mode)
{
        autofree(BootManager) *m = NULL;
        PlaygroundConfig start_conf = { 0 };

        m = prepare_playground(&start_conf);
        fail_if(!m, "Fatal: Cannot initialise playground");
        boot_manager_set_image_mode(m, image_mode);

        fail_if(!boot_manager_modify_bootloader(m, BOOTLOADER_OPERATION_INSTALL),
                "Failed to install bootloader");

        confirm_bootloader();
        fail_if(!confirm_bootloader_match(), "Installed bootloader is incorrect");

        fail_if(!push_bootloader_update(1), "Failed to bump source bootloader");
        fail_if(confirm_bootloader_match(), "Source shouldn't match target bootloader yet");

        fail_if(!boot_manager_modify_bootloader(m,
                                                BOOTLOADER_OPERATION_UPDATE |
                                                    BOOTLOADER_OPERATION_NO_CHECK),
                "Failed to forcibly update bootloader");
        confirm_bootloader();
        fail_if(!confirm_bootloader_match(), "Bootloader didn't actually update");

        /* We're in sync */
        fail_if(boot_manager_needs_update(m), "Bootloader lied about needing an update");

        fail_if(!push_bootloader_update(2), "Failed to bump source bootloader");
        /* Pushed out of sync, should need update */
        fail_if(!boot_manager_needs_update(m), "Bootloader doesn't know it needs update");
        fail_if(!boot_manager_modify_bootloader(m, BOOTLOADER_OPERATION_UPDATE),
                "Failed to auto-update bootloader");
        fail_if(!confirm_bootloader_match(), "Auto-updated bootloader doesn't match source");
}

START_TEST(bootman_loader_test_update_image)
{
        internal_loader_test(true);
}
END_TEST

START_TEST(bootman_loader_test_update_native)
{
        internal_loader_test(false);
}
END_TEST

START_TEST(bootman_loader_test_autoupdate)
{
        autofree(BootManager) *m = NULL;

        PlaygroundKernel init_kernels[] = {
                { "4.6.0", "native", 180, true },
                { "4.4.4", "native", 160, false },
                { "4.4.0", "native", 140, false },
        };
        PlaygroundConfig start_conf = { "4.4.4-160.native",
                                        init_kernels,
                                        ARRAY_SIZE(init_kernels) };

        m = prepare_playground(&start_conf);
        fail_if(!m, "Fatal: Cannot initialise playground");
        boot_manager_set_image_mode(m, false);

        fail_if(!boot_manager_update(m), "Failed to initialise filesystem");
        confirm_bootloader();

        fail_if(!push_bootloader_update(2), "Failed to bump bootloader revision");

        fail_if(!boot_manager_update(m), "Failed to resync the filesystem");
        confirm_bootloader();

        fail_if(!confirm_bootloader_match(), "Autoupdate of bootloader failed");
}
END_TEST

START_TEST(bootman_test_retain_booted)
{
        autofree(BootManager) *m = NULL;

        PlaygroundKernel init_kernels[] = {
                { "4.6.0", "native", 180, true },  /* Latest */
                { "4.6.0", "native", 170, false }, /* Newer update */
                { "4.4.4", "native", 160, false }, /* Booted */
                { "4.4.0", "native", 140, false }, /* Curveball, not booted. */
                { "4.2.0", "native", 120, false }, /* Actually did boot */
        };
        PlaygroundConfig start_conf = { "4.4.4-160.native",
                                        init_kernels,
                                        ARRAY_SIZE(init_kernels) };

        m = prepare_playground(&start_conf);
        fail_if(!m, "Fatal: Cannot initialise playground");
        boot_manager_set_image_mode(m, false);

        fail_if(!set_kernel_booted(&init_kernels[4], true), "Failed to set kernel as booted");

        fail_if(!boot_manager_update(m), "Failed to update in native mode");

        /* Ensure new default-native is retained */
        fail_if(!confirm_kernel_installed(m, &(init_kernels[0])),
                "Failed to retain latest default kernel");

        /* Middle update was useless for us  */
        fail_if(confirm_kernel_installed(m, &(init_kernels[1])),
                "Non-booted non-default kernel shouldn't be installed.");

        /* Currently booted kernel - must stay! */
        fail_if(!confirm_kernel_installed(m, &(init_kernels[2])),
                "Failed to retain running kernel!");

        /* Old unused kernel, didn't boot. */
        fail_if(confirm_kernel_installed(m, &(init_kernels[3])),
                "Non-booted old kernel shouldn't be installed.");

        /* Last booted good guy */
        fail_if(!confirm_kernel_installed(m, &(init_kernels[4])),
                "Failed to retain the last running kernel");
}
END_TEST

/**
 * Test retention of multiple types..
 */
START_TEST(bootman_test_retain_multi)
{
        autofree(BootManager) *m = NULL;

        PlaygroundKernel init_kernels[] = {
                { "4.6.0", "native", 180, true },  /* Tip native */
                { "4.4.4", "native", 160, false }, /* Extranous */
                { "4.2.2", "native", 140, false }, /* Did boot */

                { "4.6.0", "kvm", 180, true },  /* Tip KVM */
                { "4.4.4", "kvm", 160, false }, /* Current kernel */
                { "4.2.2", "kvm", 140, false }, /* Never booted */
        };

        PlaygroundConfig start_conf = { "4.4.4-160.kvm", init_kernels, ARRAY_SIZE(init_kernels) };

        m = prepare_playground(&start_conf);
        fail_if(!m, "Fatal: Cannot initialise playground");
        boot_manager_set_image_mode(m, false);

        fail_if(!set_kernel_booted(&(init_kernels[2]), true), "Failed to set the booted kernel");

        fail_if(!boot_manager_update(m), "Failed to update with multi kernels");

        /* Check the tips */
        fail_if(!confirm_kernel_installed(m, &(init_kernels[0])),
                "Tip native kernel not installed");
        fail_if(!confirm_kernel_installed(m, &(init_kernels[3])), "Tip kvm kernel not installed");

        /* Extranous */
        fail_if(confirm_kernel_installed(m, &(init_kernels[1])),
                "Extranous native kernel should be uninstalled!");
        fail_if(confirm_kernel_installed(m, &(init_kernels[5])),
                "Never-booted excess KVM kernel shouldn't be installed");

        /* Did boot, needs to stay */
        fail_if(!confirm_kernel_installed(m, &(init_kernels[2])),
                "Last booting native kernel isn't installed");

        /* And finally, is our running kernel still around? Kinda important. */
        fail_if(!confirm_kernel_installed(m, &(init_kernels[4])),
                "Running kernel has gone walkabouts");
}
END_TEST

static Suite *core_suite(void)
{
        Suite *s = NULL;
        TCase *tc = NULL;

        s = suite_create("bootman_update");

        tc = tcase_create("bootman_loader_functions");
        tcase_add_test(tc, bootman_loader_test_update_image);
        tcase_add_test(tc, bootman_loader_test_update_native);
        tcase_add_test(tc, bootman_loader_test_autoupdate);
        suite_add_tcase(s, tc);

        tc = tcase_create("bootman_update_functions");
        tcase_add_test(tc, bootman_image_test_simple);
        tcase_add_test(tc, bootman_native_test_simple);
        tcase_add_test(tc, bootman_test_retain_booted);
        tcase_add_test(tc, bootman_test_retain_multi);
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

        /* Override vtable for safety */
        cbm_blkid_set_vtable(&BlkidTestOps);

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
