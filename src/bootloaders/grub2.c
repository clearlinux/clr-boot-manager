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

/**
 * Remove /vmlinuz & /initrd.img
 * Create /etc/grub.d/10_$nom
 * Run grub-mkconfig -o /boot/grub/grub.cfg
 * Recreate symlinks for default
 */

#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "bootloader.h"
#include "config.h"
#include "files.h"
#include "log.h"
#include "nica/files.h"
#include "system_stub.h"
#include "util.h"
#include "writer.h"

/**
 * Inspired by/modelled on, /etc/grub.d/10_linux
 * Each CBM entry is a unique script, so there is no caching between multiple
 * entries.
 */
#define GRUB2_10LINUX_CACHE                                                                        \
        "\
        if [[ \"${dirname}\" = \"/\" ]]; then\n\
                prep_root=\"$(prepare_grub_to_access_device ${GRUB_DEVICE} | grub_add_tab)\"\n\
                printf '%s\\n' \"${prep_root}\" | sed \"s/^/$submenu_indentation/\"\n\
        else\n\
                prep_root=\"$(prepare_grub_to_access_device ${GRUB_DEVICE_BOOT} | grub_add_tab)\"\n\
                printf '%s\\n' \"${prep_root}\" | sed \"s/^/$submenu_indentation/\"\n\
        fi\n\
"

/**
 * Form the full path to the GRUB2 configuration script
 */
static inline char *grub2_get_entry_path_for_kernel(BootManager *manager, const Kernel *kernel)
{
        return string_printf("%s/etc/grub.d/10_%s_%s-%d.%s",
                             boot_manager_get_prefix(manager),
                             boot_manager_get_os_id(manager),
                             kernel->meta.version,
                             kernel->meta.release,
                             kernel->meta.ktype);
}

/**
 * If /boot is mounted, we already now know its a separate boot partition, so
 * accommodate for it.
 */
static inline bool grub2_is_separate_boot_partition(void)
{
        return cbm_system_is_mounted(BOOT_DIRECTORY);
}

/**
 * Return relative dir, i.e. instead of /boot, boot
 */
static inline char *grub2_get_boot_relative(void)
{
        static char *grub_bootdir = BOOT_DIRECTORY;
        return string_printf("%s", grub_bootdir + 1);
}

bool grub2_init(__cbm_unused__ const BootManager *manager)
{
        return true;
}

void grub2_destroy(__cbm_unused__ const BootManager *manager)
{
}

bool grub2_install_kernel(const BootManager *manager, const Kernel *kernel)
{
        if (!manager || !kernel) {
                return false;
        }

        autofree(CbmWriter) *writer = CBM_WRITER_INIT;
        autofree(char) *grub_dir = NULL;
        const CbmDeviceProbe *root_dev = NULL;
        const char *os_name = NULL;
        const char *os_id = NULL;
        autofree(char) *old_conf = NULL;
        autofree(char) *conf_path = NULL;
        autofree(char) *boot_dir = NULL;
        const char *prefix = NULL;
        bool is_separate;

        if (!cbm_writer_open(writer)) {
                return false;
        }

        prefix = boot_manager_get_prefix((BootManager *)manager);

        root_dev = boot_manager_get_root_device((BootManager *)manager);
        if (!root_dev) {
                LOG_FATAL("Root device unknown, this should never happen! %s", kernel->source.path);
                return false;
        }

        is_separate = grub2_is_separate_boot_partition();
        boot_dir = grub2_get_boot_relative();

        os_name = boot_manager_get_os_name((BootManager *)manager);
        os_id = boot_manager_get_os_id((BootManager *)manager);

        /* Write out the stock header for our script */
        cbm_writer_append(writer, "#!/bin/bash\nset -e\n");
        cbm_writer_append(writer, ". \"/usr/share/grub/grub-mkconfig_lib\"\n");

        /* Write the start of the entry
         * e.g. menuentry 'Some Linux OS (4.4.9-12.lts)' --class some-linux-os --class gnu-linux
         * --class gnu --class os
         */
        cbm_writer_append_printf(
            writer,
            "echo \"menuentry '%s (%s-%d.%s)' --class %s --class gnu-linux --class gnu --class os",
            os_name,
            kernel->meta.version,
            kernel->meta.release,
            kernel->meta.ktype,
            os_id);
        /* Finish it off with a unique menu ID and escape the bash variable */
        cbm_writer_append_printf(writer,
                                 " \\$menuentry_id_option '%s-%s-%d.%s' {\"\n",
                                 os_id,
                                 kernel->meta.version,
                                 kernel->meta.release,
                                 kernel->meta.ktype);

        /* Load video, compatibility with 10_linux */
        cbm_writer_append(writer, "        if [ \"x$GRUB_GFXPAYLOAD_LINUX\" = x ]; then\n");
        cbm_writer_append(writer, "                echo \"        load_video\"\n");
        cbm_writer_append(writer, "        fi\n");

        /* Always load gzio */
        cbm_writer_append(writer, "echo \"        insmod gzio\"\n");

        /* TODO: Load root cache */
        const char *cache = GRUB2_10LINUX_CACHE;
        cbm_writer_append(writer, cache);

        /* Add the main loader lines */
        cbm_writer_append_printf(writer,
                                 "echo \"        echo 'Loading %s %s ...'\"\n",
                                 os_name,
                                 kernel->meta.version);
        if (is_separate) {
                cbm_writer_append_printf(writer,
                                         "echo \"        linux /%s UUID=%s ",
                                         kernel->target.path,
                                         root_dev->uuid);
        } else {
                cbm_writer_append_printf(writer,
                                         "echo \"        linux %s/%s UUID=%s ",
                                         BOOT_DIRECTORY, /* i.e. /boot */
                                         kernel->target.path,
                                         root_dev->uuid);
        }

        if (root_dev->luks_uuid) {
                cbm_writer_append_printf(writer, "rd.luks.uuid=%s ", root_dev->luks_uuid);
        }

        /* Finish it off with the command line options */
        cbm_writer_append_printf(writer, "%s\"\n", kernel->meta.cmdline);

        /* Optional initrd */
        if (kernel->target.initrd_path) {
                cbm_writer_append(writer, "echo \"        echo 'Loading initial ramdisk'\"\n");
                if (is_separate) {
                        cbm_writer_append_printf(writer,
                                                 "echo \"        initrd /%s\"\n",
                                                 kernel->target.initrd_path);
                } else {
                        cbm_writer_append_printf(writer,
                                                 "echo \"        initrd %s/%s\"\n",
                                                 BOOT_DIRECTORY, /* i.e. /boot */
                                                 kernel->target.initrd_path);
                }
        }

        /* Finalize the entry */
        cbm_writer_append(writer, "echo \"}\"\n");

        cbm_writer_close(writer);

        conf_path = grub2_get_entry_path_for_kernel((BootManager *)manager, kernel);

        /* If our new config matches the old config, just return. */
        if (file_get_text(conf_path, &old_conf)) {
                if (streq(old_conf, writer->buffer)) {
                        return true;
                }
        }

        /* Ensure the grub.d directory actually exists (should do..) */
        grub_dir = string_printf("%s/etc/grub.d", prefix);
        if (!nc_file_exists(grub_dir) && !nc_mkdir_p(grub_dir, 00755)) {
                LOG_FATAL("Failed to create grub.d dir: %s [%s]", grub_dir, strerror(errno));
                return false;
        }

        if (!file_set_text(conf_path, writer->buffer)) {
                LOG_FATAL("Failed to create loader entry for: %s [%s]",
                          kernel->source.path,
                          strerror(errno));
                return false;
        }

        /* Ensure it's executable */
        if (chmod(conf_path, 00755) != 0) {
                LOG_FATAL("Failed to mark loader entry as executable: %s [%s]",
                          kernel->source.path,
                          strerror(errno));
                return false;
        }

        cbm_sync();

        return true;
}

bool grub2_remove_kernel(const BootManager *manager, const Kernel *kernel)
{
        if (!manager || !kernel) {
                return false;
        }
        autofree(char) *conf_path = NULL;

        conf_path = grub2_get_entry_path_for_kernel((BootManager *)manager, kernel);
        if (nc_file_exists(conf_path) && unlink(conf_path) < 0) {
                LOG_FATAL("grub2_remove_kernel: Failed to remove %s: %s",
                          conf_path,
                          strerror(errno));
                return false;
        }
        return true;
}

bool grub2_set_default_kernel(const BootManager *manager, const Kernel *default_kernel)
{
        if (!manager) {
                return false;
        }
        autofree(char) *vmlinuz_path = NULL;
        autofree(char) *initrd_path = NULL;
        autofree(char) *command = NULL;
        autofree(char) *boot_dir = NULL;
        autofree(char) *grub_dir = NULL;
        autofree(char) *vmlinuz_rel = NULL;
        autofree(char) *initrd_rel = NULL;
        autofree(char) *boot_rel = NULL;
        const char *prefix = NULL;
        int ret;

        prefix = boot_manager_get_prefix((BootManager *)manager);
        boot_dir = boot_manager_get_boot_dir((BootManager *)manager);
        vmlinuz_path = string_printf("%s/vmlinuz", prefix);
        initrd_path = string_printf("%s/initrd.img", prefix);

        /* Always nuke the files *before* running grub-mkconfig to stop duped
         * entries being created */
        if (nc_file_exists(vmlinuz_path) && unlink(vmlinuz_path) < 0) {
                LOG_ERROR("grub2_set_default_kernel: Failed to remove %s: %s",
                          vmlinuz_path,
                          strerror(errno));
                return false;
        }

        if (nc_file_exists(initrd_path) && unlink(initrd_path) < 0) {
                LOG_FATAL("grub2_set_default_kernel: Failed to remove %s: %s",
                          initrd_path,
                          strerror(errno));
                return false;
        }

        /* Ensure the GRUB2 directory tree exists */
        grub_dir = string_printf("%s/grub", boot_dir);
        if (!nc_file_exists(grub_dir) && !nc_mkdir_p(grub_dir, 00755)) {
                LOG_FATAL("grub2_set_default_kernel: Failed to mkdir %s: %s",
                          grub_dir,
                          strerror(errno));
                return false;
        }

        /* Run grub-mkconfig now */
        command = string_printf("%s/usr/sbin/grub-mkconfig -o %s/grub/grub.cfg", prefix, boot_dir);
        ret = cbm_system_system(command);
        if (ret != 0) {
                LOG_FATAL("grub2_set_default_kernel: grub-mkconfig exited with status code %d: %s",
                          ret,
                          strerror(errno));
                return false;
        }

        /* Nothing else to do here */
        if (!default_kernel) {
                return true;
        }

        /* i.e. boot */
        boot_rel = grub2_get_boot_relative();

        /* /vmlinuz -> boot/kernel-* */
        vmlinuz_rel = string_printf("%s/%s", boot_rel, default_kernel->target.legacy_path);
        if (symlink(vmlinuz_rel, vmlinuz_path) != 0) {
                LOG_FATAL("grub2_set_default_kernel: Failed to update kernel default link: %s",
                          strerror(errno));
                return false;
        }

        /* No initrd, just continue */
        if (!default_kernel->target.initrd_path) {
                return true;
        }

        /* /initrd.img -> boot/initrd-* */
        initrd_rel = string_printf("%s/%s", boot_rel, default_kernel->target.initrd_path);
        if (symlink(initrd_rel, initrd_path) != 0) {
                LOG_FATAL("grub2_set_default_kernel: Failed to update initrd default link: %s",
                          strerror(errno));
                return false;
        }

        return true;
}

bool grub2_needs_install(__cbm_unused__ const BootManager *manager)
{
        return false;
}

bool grub2_needs_update(__cbm_unused__ const BootManager *manager)
{
        return false;
}

bool grub2_install(__cbm_unused__ const BootManager *manager)
{
        /* We don't handle management of GRUB2 so we just say, yes, it did
         * install. This saves complications.
         */
        return true;
}

bool grub2_update(__cbm_unused__ const BootManager *manager)
{
        /* Likewise, we don't update. Just return true. */
        return true;
}

bool grub2_remove(__cbm_unused__ const BootManager *manager)
{
        /* Certainly not going to remove if we don't install */
        return true;
}

int grub2_get_capabilities(__cbm_unused__ const BootManager *manager)
{
        /* Or in other words, we're the last bootloader candidate. */
        return BOOTLOADER_CAP_LEGACY;
}

__cbm_export__ const BootLoader grub2_bootloader = {.name = "grub2",
                                                    .init = grub2_init,
                                                    .install_kernel = grub2_install_kernel,
                                                    .remove_kernel = grub2_remove_kernel,
                                                    .set_default_kernel = grub2_set_default_kernel,
                                                    .needs_install = grub2_needs_install,
                                                    .needs_update = grub2_needs_update,
                                                    .install = grub2_install,
                                                    .update = grub2_update,
                                                    .remove = grub2_remove,
                                                    .destroy = grub2_destroy,
                                                    .get_capabilities = grub2_get_capabilities };

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
