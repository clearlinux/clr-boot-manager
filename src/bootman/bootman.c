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
#include <errno.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "bootloader.h"
#include "bootman.h"
#include "bootman_private.h"
#include "cmdline.h"
#include "files.h"
#include "log.h"
#include "nica/files.h"

#include "config.h"

/**
 * Currently only support systemd_bootloader
 */

extern const BootLoader systemd_bootloader;
extern const BootLoader gummiboot_bootloader;
extern const BootLoader goofiboot_bootloader;
extern const BootLoader syslinux_bootloader;

BootManager *boot_manager_new()
{
        struct BootManager *r = NULL;
        struct utsname uts = { 0 };

        r = calloc(1, sizeof(struct BootManager));
        if (!r) {
                return NULL;
        }

        /* Try to parse the currently running kernel */
        if (uname(&uts) == 0) {
                if (!boot_manager_set_uname(r, uts.release)) {
                        LOG_WARNING("Unable to parse the currently running kernel: %s",
                                    uts.release);
                }
        }

        /* CLI can override this */
        boot_manager_set_image_mode(r, false);

        return r;
}

void boot_manager_free(BootManager *self)
{
        if (!self) {
                return;
        }

        if (self->bootloader) {
                self->bootloader->destroy(self);
        }

        if (self->os_release) {
                cbm_os_release_free(self->os_release);
        }

        cbm_free_sysconfig(self->sysconfig);
        free(self->kernel_dir);
        free(self->abs_bootdir);
        free(self->cmdline);
        free(self);
}

bool boot_manager_set_prefix(BootManager *self, char *prefix)
{
        assert(self != NULL);

        char *kernel_dir = NULL;
        SystemConfig *config = NULL;

        if (!prefix) {
                return false;
        }

        cbm_free_sysconfig(self->sysconfig);
        self->sysconfig = NULL;

        config = cbm_inspect_root(prefix);
        if (!config) {
                return false;
        }
        self->sysconfig = config;

        if (self->kernel_dir) {
                free(self->kernel_dir);
                self->kernel_dir = NULL;
        }

        kernel_dir = string_printf("%s/%s", config->prefix, KERNEL_DIRECTORY);

        if (self->kernel_dir) {
                free(self->kernel_dir);
        }
        self->kernel_dir = kernel_dir;

        if (self->bootloader) {
                self->bootloader->destroy(self);
                self->bootloader = NULL;
        }

        if (self->os_release) {
                cbm_os_release_free(self->os_release);
                self->os_release = NULL;
        }

        self->os_release = cbm_os_release_new_for_root(prefix);
        if (!self->os_release) {
                DECLARE_OOM();
                abort();
        }

        /* Load cmdline */
        if (self->cmdline) {
                free(self->cmdline);
                self->cmdline = NULL;
        }
        self->cmdline = cbm_parse_cmdline_files(config->prefix);

        /* Find legacy */
        if (config->legacy) {
                LOG_DEBUG("Legacy boot now selected (syslinux)");
                self->bootloader = &syslinux_bootloader;
        } else {
/* Use the bootloader selected at compile time */
#if defined(HAVE_SYSTEMD_BOOT)
                self->bootloader = &systemd_bootloader;
#elif defined(HAVE_GUMMIBOOT)
                self->bootloader = &gummiboot_bootloader;
#else
                self->bootloader = &goofiboot_bootloader;
#endif
                LOG_DEBUG("UEFI boot now selected (%s)", self->bootloader->name);
        }
        if (!self->bootloader->init(self)) {
                self->bootloader->destroy(self);
                LOG_FATAL("Cannot initialise bootloader %s", self->bootloader->name);
                return false;
        }

        return true;
}

const char *boot_manager_get_prefix(BootManager *self)
{
        assert(self != NULL);

        return (const char *)self->sysconfig->prefix;
}

const char *boot_manager_get_kernel_dir(BootManager *self)
{
        assert(self != NULL);

        return (const char *)self->kernel_dir;
}

const char *boot_manager_get_vendor_prefix(__cbm_unused__ BootManager *self)
{
        return VENDOR_PREFIX;
}

const char *boot_manager_get_os_name(BootManager *self)
{
        assert(self != NULL);
        assert(self->os_release != NULL);

        return cbm_os_release_get_value(self->os_release, OS_RELEASE_PRETTY_NAME);
}

const CbmDeviceProbe *boot_manager_get_root_device(BootManager *self)
{
        assert(self != NULL);
        assert(self->sysconfig != NULL);

        return (const CbmDeviceProbe *)self->sysconfig->root_device;
}

bool boot_manager_install_kernel(BootManager *self, const Kernel *kernel)
{
        assert(self != NULL);

        if (!kernel || !self->bootloader) {
                return false;
        }
        if (!cbm_is_sysconfig_sane(self->sysconfig)) {
                return false;
        }

        /* Install the kernel blob first */
        if (!boot_manager_install_kernel_internal(self, kernel)) {
                return false;
        }
        /* Hand over to the bootloader to finish it up */
        return self->bootloader->install_kernel(self, kernel);
}

bool boot_manager_remove_kernel(BootManager *self, const Kernel *kernel)
{
        assert(self != NULL);

        if (!kernel || !self->bootloader) {
                return false;
        }
        if (!cbm_is_sysconfig_sane(self->sysconfig)) {
                return false;
        }
        /* Remove the kernel blob first */
        if (!boot_manager_remove_kernel_internal(self, kernel)) {
                return false;
        }
        /* Hand over to the bootloader to finish it up */
        return self->bootloader->remove_kernel(self, kernel);
}

bool boot_manager_set_default_kernel(BootManager *self, const Kernel *kernel)
{
        assert(self != NULL);

        if (!self->bootloader) {
                return false;
        }
        if (!cbm_is_sysconfig_sane(self->sysconfig)) {
                return false;
        }
        return self->bootloader->set_default_kernel(self, kernel);
}

char *boot_manager_get_boot_dir(BootManager *self)
{
        assert(self != NULL);
        assert(self->sysconfig != NULL);

        char *ret = NULL;

        if (self->abs_bootdir) {
                return strdup(self->abs_bootdir);
        }

        ret = string_printf("%s%s", self->sysconfig->prefix, BOOT_DIRECTORY);
        return ret;
}

bool boot_manager_set_boot_dir(BootManager *self, const char *bootdir)
{
        assert(self != NULL);

        if (!bootdir) {
                return false;
        }
        if (self->abs_bootdir) {
                free(self->abs_bootdir);
        }
        self->abs_bootdir = strdup(bootdir);
        if (!self->abs_bootdir) {
                return false;
        }

        if (!self->bootloader) {
                return true;
        }
        self->bootloader->destroy(self);
        if (!self->bootloader->init(self)) {
                /* Ensure cleanup. */
                self->bootloader->destroy(self);
                LOG_FATAL("Re-initialisation of bootloader failed");
                return false;
        }
        return true;
}

bool boot_manager_modify_bootloader(BootManager *self, BootLoaderOperation op)
{
        assert(self != NULL);

        if (!self->bootloader) {
                return false;
        }

        if (!cbm_is_sysconfig_sane(self->sysconfig)) {
                return false;
        }

        if (op & BOOTLOADER_OPERATION_INSTALL) {
                if (op & BOOTLOADER_OPERATION_NO_CHECK) {
                        return self->bootloader->install(self);
                }
                if (self->bootloader->needs_install(self)) {
                        return self->bootloader->install(self);
                }
                return true;
        } else if (op & BOOTLOADER_OPERATION_REMOVE) {
                return self->bootloader->remove(self);
        } else if (op & BOOTLOADER_OPERATION_UPDATE) {
                if (op & BOOTLOADER_OPERATION_NO_CHECK) {
                        return self->bootloader->update(self);
                }
                if (self->bootloader->needs_update(self)) {
                        return self->bootloader->update(self);
                }
                return true;
        } else {
                LOG_FATAL("Unknown bootloader operation");
                return false;
        }
}

bool boot_manager_is_image_mode(BootManager *self)
{
        assert(self != NULL);

        return self->image_mode;
}

void boot_manager_set_image_mode(BootManager *self, bool image_mode)
{
        assert(self != NULL);

        self->image_mode = image_mode;
}

bool boot_manager_needs_install(BootManager *self)
{
        assert(self != NULL);

        return self->bootloader->needs_install(self);
}

bool boot_manager_needs_update(BootManager *self)
{
        assert(self != NULL);

        return self->bootloader->needs_update(self);
}

bool boot_manager_set_uname(BootManager *self, const char *uname)
{
        assert(self != NULL);

        if (!uname) {
                return false;
        }
        SystemKernel k = { 0 };
        bool have_sys_kernel = cbm_parse_system_kernel(uname, &k);
        if (!have_sys_kernel) {
                LOG_ERROR("Failed to parse given uname release: %s", uname);
                self->have_sys_kernel = false;
                return false;
        }
        LOG_INFO("Current running kernel: %s", uname);

        memcpy(&(self->sys_kernel), &k, sizeof(struct SystemKernel));
        self->have_sys_kernel = have_sys_kernel;
        return self->have_sys_kernel;
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
