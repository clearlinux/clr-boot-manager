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
#include <ctype.h>

#include "bootloader.h"
#include "bootman.h"
#include "bootman_private.h"
#include "cmdline.h"
#include "files.h"
#include "log.h"
#include "nica/files.h"

#include "config.h"

/**
 * Total "usable" bootloaders
 */
extern const BootLoader grub2_bootloader;
#if defined(HAVE_SHIM_SYSTEMD_BOOT)
extern const BootLoader shim_systemd_bootloader;
#endif
extern const BootLoader systemd_bootloader;
extern const BootLoader syslinux_bootloader;

/**
 * Bootloader set that we're allowed to check and use
 */
const BootLoader *bootman_known_loaders[] =
    { &grub2_bootloader, /**<Always place first to allow syslinux to override */
#if defined(HAVE_SHIM_SYSTEMD_BOOT)
      &shim_systemd_bootloader,
#elif defined(HAVE_SYSTEMD_BOOT)
      &systemd_bootloader,
#endif
      /* non-systemd-class */
      &syslinux_bootloader };

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

        r->initrd_freestanding = nc_hashmap_new_full(nc_string_hash, nc_string_compare, free, free);
        OOM_CHECK(r->initrd_freestanding);


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
        free(self->initrd_freestanding_dir);
        nc_hashmap_free(self->initrd_freestanding);
        free(self->abs_bootdir);
        free(self->cmdline);
        free(self);
}

static bool boot_manager_select_bootloader(BootManager *self)
{
        const BootLoader *selected = NULL;
        int selected_boot_mask = 0;
        int wanted_boot_mask = self->sysconfig->wanted_boot_mask;

        /* Select a bootloader based on the capabilities */
        for (size_t i = 0; i < ARRAY_SIZE(bootman_known_loaders); i++) {
                const BootLoader *l = bootman_known_loaders[i];
                selected_boot_mask = l->get_capabilities(self);
                if ((selected_boot_mask & wanted_boot_mask) == wanted_boot_mask) {
                        selected = l;
                        break;
                }
        }

        if (!selected) {
                LOG_FATAL("Failed to find an appropriate bootloader for this system");
                return false;
        }

        self->bootloader = selected;

        /* Emit debug bits */
        if ((wanted_boot_mask & BOOTLOADER_CAP_UEFI) == BOOTLOADER_CAP_UEFI) {
                LOG_DEBUG("UEFI boot now selected (%s)", self->bootloader->name);
        } else {
                LOG_DEBUG("Legacy boot now selected (%s)", self->bootloader->name);
        }

        /* Finally, initialise the bootloader itself now */
        if (!self->bootloader->init(self)) {
                self->bootloader->destroy(self);
                LOG_FATAL("Cannot initialise bootloader %s", self->bootloader->name);
                return false;
        }

        return true;
}

bool boot_manager_set_prefix(BootManager *self, char *prefix)
{
        assert(self != NULL);

        char *kernel_dir = NULL;
        char *initrd_dir = NULL;
        SystemConfig *config = NULL;

        if (!prefix) {
                return false;
        }

        cbm_free_sysconfig(self->sysconfig);
        self->sysconfig = NULL;

        config = cbm_inspect_root(prefix, self->image_mode);
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

        initrd_dir = string_printf("%s/%s", config->prefix, INITRD_DIRECTORY);

        if (self->initrd_freestanding_dir) {
                free(self->initrd_freestanding_dir);
        }
        self->initrd_freestanding_dir = initrd_dir;

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

        if (!boot_manager_select_bootloader(self)) {
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

const char *boot_manager_get_os_id(BootManager *self)
{
        assert(self != NULL);
        assert(self->os_release != NULL);

        return cbm_os_release_get_value(self->os_release, OS_RELEASE_ID);
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
        char *realp = NULL;

        if (self->abs_bootdir) {
                return strdup(self->abs_bootdir);
        }

        ret = string_printf("%s%s", self->sysconfig->prefix, BOOT_DIRECTORY);

        /* Attempt to resolve it first, removing double slashes */
        realp = realpath(ret, NULL);
        if (realp) {
                free(ret);
                return realp;
        }

        return ret;
}

bool boot_manager_set_boot_dir(BootManager *self, const char *bootdir)
{
        assert(self != NULL);

        if (!bootdir) {
                return false;
        }
        /* Take early copy as we may actually be resetting to our own currently
         * set (allocated) bootdir */
        char *nboot = strdup(bootdir);
        if (!nboot) {
                return false;
        }

        if (self->abs_bootdir) {
                free(self->abs_bootdir);
        }
        self->abs_bootdir = nboot;

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

bool boot_manager_modify_bootloader(BootManager *self, int flags)
{
        assert(self != NULL);
        autofree(char) *boot_dir = NULL;

        if (!self->bootloader) {
                return false;
        }

        if (!cbm_is_sysconfig_sane(self->sysconfig)) {
                return false;
        }

        /* Ensure we're up to date here on the bootloader */
        boot_dir = boot_manager_get_boot_dir(self);
        if (!boot_manager_set_boot_dir(self, boot_dir)) {
                return false;
        }

        bool nocheck = (flags & BOOTLOADER_OPERATION_NO_CHECK) == BOOTLOADER_OPERATION_NO_CHECK;

        if ((flags & BOOTLOADER_OPERATION_INSTALL) == BOOTLOADER_OPERATION_INSTALL) {
                if (nocheck) {
                        return self->bootloader->install(self);
                }
                if (self->bootloader->needs_install(self)) {
                        return self->bootloader->install(self);
                }
                return true;
        } else if ((flags & BOOTLOADER_OPERATION_REMOVE) == BOOTLOADER_OPERATION_REMOVE) {
                return self->bootloader->remove(self);
        } else if ((flags & BOOTLOADER_OPERATION_UPDATE) == BOOTLOADER_OPERATION_UPDATE) {
                if (nocheck) {
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

bool boot_manager_enumerate_initrds_freestanding(BootManager *self)
{
        autofree(DIR) *initrd_dir = NULL;
        struct dirent *ent = NULL;
        struct stat st = { 0 };

        if (!self || !self->initrd_freestanding_dir) {
                return false;
        }

        initrd_dir = opendir(self->initrd_freestanding_dir);
        if (!initrd_dir) {
                if (errno == ENOENT) {
                        LOG_INFO("path %s does not exist", self->initrd_freestanding_dir);
                        return true;
                } else {
                        LOG_ERROR("Error opening %s: %s", self->initrd_freestanding_dir, strerror(errno));
                        return false;
                }
        }

        while ((ent = readdir(initrd_dir)) != NULL) {
                char *initrd_name_key = NULL;
                char *initrd_name_val = NULL;
                autofree(char) *path = NULL;

                path = string_printf("%s/%s", self->initrd_freestanding_dir, ent->d_name);

                /* Some kind of broken link */
                if (lstat(path, &st) != 0) {
                        continue;
                }

                /* Regular only */
                if (!S_ISREG(st.st_mode)) {
                        continue;
                }

                /* empty files are skipped too */
                if (st.st_size == 0) {
                        continue;
                }

                initrd_name_val = strdup(ent->d_name);
                OOM_CHECK(initrd_name_val);

                initrd_name_key = string_printf("freestanding-%s", ent->d_name);
                OOM_CHECK(initrd_name_key);

                if (!nc_hashmap_put(self->initrd_freestanding, initrd_name_key, initrd_name_val)) {
                        free(initrd_name_key);
                        free(initrd_name_val);
                        DECLARE_OOM();
                        abort();
                }
        }
        return true;
}

bool boot_manager_copy_initrd_freestanding(BootManager *self)
{
        autofree(char) *base_path = NULL;
        NcHashmapIter iter = { 0 };
        void *key = NULL;
        void *val = NULL;
        bool is_uefi = ((self->bootloader->get_capabilities(self) & BOOTLOADER_CAP_UEFI) ==
                        BOOTLOADER_CAP_UEFI);
        const char *efi_boot_dir =
            is_uefi ? self->bootloader->get_kernel_destination(self) : NULL;
        base_path = boot_manager_get_boot_dir((BootManager *)self);
        if (!self || !self->initrd_freestanding_dir || !self->initrd_freestanding) {
                return false;
        }

        /* if it's UEFI, then bootloader->get_kernel_dst() must return a value. */
        if (is_uefi && !efi_boot_dir) {
                return false;
        }

        nc_hashmap_iter_init(self->initrd_freestanding, &iter);
        while (nc_hashmap_iter_next(&iter, &key, &val)) {
                autofree(char) *initrd_target = NULL;
                autofree(char) *initrd_source = NULL;

                initrd_target = string_printf("%s%s/%s",
                                              base_path,
                                              (is_uefi ? efi_boot_dir : ""),
                                              (char*)key);
                initrd_source = string_printf("%s/%s",
                                              self->initrd_freestanding_dir,
                                              (char*)val);
                if (!cbm_files_match(initrd_source, initrd_target)) {
                        if (!copy_file_atomic(initrd_source, initrd_target, 00644)) {
                                LOG_FATAL("Failed to install initrd %s: %s",
                                          initrd_target,
                                          strerror(errno));
                                return false;
                        }
                }
        }
        return true;
}

bool boot_manager_remove_initrd_freestanding(BootManager * self)
{
        autofree(char) *base_path = NULL;
        autofree(char) *initrd_efi_path = NULL;
        autofree(DIR) *initrd_dir = NULL;
        struct dirent *ent = NULL;
        bool is_uefi = ((self->bootloader->get_capabilities(self) & BOOTLOADER_CAP_UEFI) ==
                        BOOTLOADER_CAP_UEFI);
        const char *efi_boot_dir =
            is_uefi ? self->bootloader->get_kernel_destination(self) : NULL;
        if (!self || !self->initrd_freestanding_dir) {
                return false;
        }
        /* if it's UEFI, then bootloader->get_kernel_dst() must return a value. */
        if (is_uefi && !efi_boot_dir) {
                return false;
        }

        base_path = boot_manager_get_boot_dir((BootManager *)self);

        initrd_efi_path = string_printf("%s/%s",
                                        base_path,
                                        (is_uefi ? efi_boot_dir : ""));

        initrd_dir = opendir(initrd_efi_path);
        if (!initrd_dir) {
                LOG_ERROR("Error opening %s: %s", initrd_efi_path, strerror(errno));
                return false;
        }

        while ((ent = readdir(initrd_dir)) != NULL) {
                autofree(char) *initrd_target = NULL;

                if (strstr(ent->d_name, "freestanding-") != ent->d_name) {
                        continue;
                }

                if (!nc_hashmap_get(self->initrd_freestanding, ent->d_name)) {
                        initrd_target = string_printf("%s/%s",
                                                      initrd_efi_path,
                                                      ent->d_name);
                        /* Remove old initrd */
                        if (nc_file_exists(initrd_target)) {
                                if (unlink(initrd_target) < 0) {
                                        LOG_ERROR("Failed to remove legacy-path UEFI initrd %s: %s",
                                                  initrd_target,
                                                  strerror(errno));
                                        return false;
                                }
                        }
                }
        }
        return true;
}

void boot_manager_initrd_iterator_init(const BootManager *manager, NcHashmapIter *iter)
{
        if (!iter) {
                return;
        }
        nc_hashmap_iter_init(manager->initrd_freestanding, iter);
}

bool boot_manager_initrd_iterator_next(NcHashmapIter *iter, char **name)
{
        if (!iter || !name) {
                return false;
        }
        return nc_hashmap_iter_next(iter, (void **)name, NULL);
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
