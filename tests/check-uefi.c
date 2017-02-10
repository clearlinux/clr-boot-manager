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

START_TEST(bootman_uefi_native)
{
        autofree(BootManager) *m = NULL;

        m = prepare_playground(&uefi_config);
        fail_if(!m, "Failed to prepare update playground");
        boot_manager_set_image_mode(m, false);

        fail_if(!set_kernel_booted(&uefi_kernels[1], true), "Failed to set kernel as booted");

        fail_if(!boot_manager_update(m), "Failed to update in native mode");

        /* Latest kernel for us */
        fail_if(!confirm_kernel_installed(m, &uefi_config, &(uefi_kernels[0])),
                "Newest kernel not installed");

        /* Running kernel */
        fail_if(!confirm_kernel_installed(m, &uefi_config, &(uefi_kernels[1])),
                "Newest kernel not installed");

        /* This guy isn't supposed to be kept around now */
        fail_if(!confirm_kernel_uninstalled(m, &(uefi_kernels[2])),
                "Uninteresting kernel shouldn't be kept around.");
}
END_TEST

/**
 * This test is designed to perform a system update to a new kernel, when the
 * current kernel cannot be detected. This ensures we can perform a transition
 * from a non cbm-managed distro to a cbm-managed one.
 *
 * Scenario:
 *
 *      - Unknown running kernel
 *      - One initial new kernel from the first update. Has never rebooted.
 *      - Update: New kernel should be installed
 *      - "Reboot", then verify running = only kernel on system
 */
START_TEST(bootman_uefi_update_from_unknown)
{
        autofree(BootManager) *m = NULL;
        PlaygroundKernel kernels[] = { { "4.2.1", "kvm", 121, true } };
        PlaygroundConfig config = { "4.2.1-121.kvm", kernels, 1, true };
        autofree(KernelArray) *pre_kernels = NULL;
        autofree(KernelArray) *post_kernels = NULL;
        Kernel *running_kernel = NULL;

        m = prepare_playground(&config);
        fail_if(!m, "Failed to prepare update playground");
        boot_manager_set_image_mode(m, false);

        /* Hax the uname */
        boot_manager_set_uname(m, "unknown-uname");

        /* Make sure pre kernels are found */
        pre_kernels = boot_manager_get_kernels(m);
        fail_if(!pre_kernels, "Failed to find kernels");
        fail_if(pre_kernels->len != 1, "Available kernels != 1");

        /* Ensure it's not booting */
        fail_if(boot_manager_get_running_kernel(m, pre_kernels) != NULL,
                "Should not find a running kernel at this point");

        /* Attempt update in this configuration */
        fail_if(!boot_manager_update(m), "Failed to update single kernel system");

        /* Now "reboot" */
        fail_if(!boot_manager_set_uname(m, "4.2.1-121.kvm"), "Failed to simulate reboot");

        /* Grab new kernels */
        post_kernels = boot_manager_get_kernels(m);
        fail_if(!post_kernels, "Failed to find kernels after update");
        fail_if(post_kernels->len != 1, "Available post kernels != 1");

        /* Check running kernel */
        running_kernel = boot_manager_get_running_kernel(m, post_kernels);
        fail_if(!running_kernel, "Failed to find kernel post reboot");
        fail_if(!streq(running_kernel->version, "4.2.1"), "Running kernel is invalid");
}
END_TEST

/**
 * Verify that we can update and install the bootloader correctly.
 *
 * Scenario:
 *
 *      - Install bootloader
 *      - Confirm initial bootloader installation
 *      - Bump bootloader data to not match
 *      - Verify bumped bootloader currently does NOT match
 *      - Request update of bootloader with *check* operation
 *      - Verify bootloader files are updated and match
 */
static void internal_loader_test(bool image_mode)
{
        autofree(BootManager) *m = NULL;
        PlaygroundConfig start_conf = {.uefi = true };

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

START_TEST(bootman_uefi_update_image)
{
        internal_loader_test(true);
}
END_TEST

START_TEST(bootman_uefi_update_native)
{
        internal_loader_test(false);
}
END_TEST

/**
 * This test is currently specific only to the UEFI bootloader support,
 * as this is the only situation whereby it is possible to completely
 * and cleanly removed a bootloader.
 *
 * Scenario:
 *
 *      - Perform installation of the bootloader
 *      - Remove it again
 *      - Validate it is legitimately gone.
 */
START_TEST(bootman_uefi_remove_bootloader)
{
        autofree(BootManager) *m = NULL;

        fail_if(!nc_file_exists(TOP_BUILD_DIR "/tests/update_playground/" BOOT_DIRECTORY
                                              "/EFI/Boot"),
                "Main EFI directory missing, botched install");

        m = prepare_playground(&uefi_config);

        /* Install bootloader once */
        fail_if(!boot_manager_modify_bootloader(m,
                                                BOOTLOADER_OPERATION_INSTALL |
                                                    BOOTLOADER_OPERATION_NO_CHECK),
                "Failed to install bootloader");
        confirm_bootloader();

        /* Now remove it again */
        fail_if(!boot_manager_modify_bootloader(m, BOOTLOADER_OPERATION_REMOVE),
                "Failed to remove the bootloader");

        /* Ensure that it is indeed removed. */
        if (boot_manager_get_architecture_size(m) == 64) {
                fail_if(nc_file_exists(TOP_BUILD_DIR "/tests/update_playground" BOOT_DIRECTORY
                                                     "/EFI/Boot/BOOTX64.EFI"),
                        "Main x64 bootloader present");
#if defined(HAVE_SYSTEMD_BOOT)
                fail_if(nc_file_exists(TOP_BUILD_DIR "/tests/update_playground/" BOOT_DIRECTORY
                                                     "/EFI/systemd"),
                        "Systemd x64 bootloader present");
#elif defined(HAVE_GUMMIBOOT)
                fail_if(nc_file_exists(TOP_BUILD_DIR "/tests/update_playground/" BOOT_DIRECTORY
                                                     "/EFI/gummiboot"),
                        "gummiboot x64 bootloader present");
#else
                fail_if(nc_file_exists(TOP_BUILD_DIR "/tests/update_playground/" BOOT_DIRECTORY
                                                     "/EFI/goofiboot"),
                        "goofiboot x64 bootloader present");
#endif
        } else {
                fail_if(nc_file_exists(TOP_BUILD_DIR "/tests/update_playground/" BOOT_DIRECTORY
                                                     "/EFI/Boot/BOOTIA32.EFI"),
                        "Main ia32 bootloader present");
#if defined(HAVE_SYSTEMD_BOOT)
                fail_if(nc_file_exists(TOP_BUILD_DIR "/tests/update_playground/" BOOT_DIRECTORY
                                                     "/EFI/systemd"),
                        "systemd-boot ia32 bootloader present");
#elif defined(HAVE_GUMMIBOOT)
                fail_if(nc_file_exists(TOP_BUILD_DIR "/tests/update_playground/" BOOT_DIRECTORY
                                                     "/EFI/gummiboot"),
                        "gummiboot ia32 bootloader present");
#else
                fail_if(nc_file_exists(TOP_BUILD_DIR "/tests/update_playground/" BOOT_DIRECTORY
                                                     "/EFI/goofiboot"),
                        "goofiboot ia32 bootloader present");
#endif
        }

        fail_if(nc_file_exists(TOP_BUILD_DIR "/tests/update_playground/" BOOT_DIRECTORY
                                             "/loader/loader.conf"),
                "systemd-class loader.conf present");
        /* DEBUG:
        __attribute__ ((unused)) int r = system("tree " TOP_BUILD_DIR "/tests/update_playground");*/
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
        tcase_add_test(tc, bootman_uefi_native);
        tcase_add_test(tc, bootman_uefi_update_from_unknown);
        tcase_add_test(tc, bootman_uefi_update_image);
        tcase_add_test(tc, bootman_uefi_update_native);
        tcase_add_test(tc, bootman_uefi_remove_bootloader);
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
