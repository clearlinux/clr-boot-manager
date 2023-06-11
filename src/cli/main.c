/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2016-2018 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cli.h"
#include "config.h"
#include "nica/hashmap.h"
#include "util.h"

#include "ops/report_booted.h"
#include "ops/timeout.h"
#include "ops/update.h"
#include "ops/kernels.h"

static SubCommand cmd_update;
static SubCommand cmd_help;
static SubCommand cmd_version;
static SubCommand cmd_set_timeout;
static SubCommand cmd_get_timeout;
static SubCommand cmd_report_booted;
static SubCommand cmd_list_kernels;
static SubCommand cmd_set_kernel;
static SubCommand cmd_remove_kernel;
static char *binary_name = NULL;
static NcHashmap *g_commands = NULL;
static bool explicit_help = false;

/**
 * Print usage
 */
static bool print_usage(int argc, char **argv)
{
        NcHashmapIter iter;
        const char *id = NULL;
        const SubCommand *command = NULL;

        if (argc >= 1 && !explicit_help) {
                command = nc_hashmap_get(g_commands, argv[0]);
                if (!command) {
                        fprintf(stderr, "Unknown topic '%s'\n", argv[0]);
                        return false;
                }
                fprintf(stdout,
                        "Usage: %s %s%s\n",
                        binary_name,
                        command->name,
                        command->usage ? command->usage : "");
                fprintf(stdout, "\n%s\n", command->help ? command->help : command->blurb);

                if (!streq(argv[0], "help") && !streq(argv[0], "version")) {
                        cli_print_default_args_help();
                }

                return true;
        }

        fprintf(stderr, "Usage: %s\n\n", binary_name);

        nc_hashmap_iter_init(g_commands, &iter);
        while (nc_hashmap_iter_next(&iter, (void **)&id, (void **)&command)) {
                fprintf(stdout, "%15s - %s\n", id, command->blurb);
        }

        cli_print_default_args_help();

        return true;
}

static bool print_version(__cbm_unused__ int argc, __cbm_unused__ char **argv)
{
        fprintf(stdout,
                PACKAGE_NAME " - version " PACKAGE_VERSION
                             "\n\
\n\
Copyright \u00A9 2016-2018 Intel Corporation\n\n\
" PACKAGE_NAME " is free software; you can redistribute it and/or modify\n\
it under the terms of the GNU Lesser General Public License as published by\n\
the Free Software Foundation; either version 2.1 of the License, or\n\
(at your option) any later version.\n");
        return true;
}

int main(int argc, char **argv)
{
        autofree(NcHashmap) *commands = NULL;
        const char *command = NULL;
        SubCommand *s_command = NULL;

        binary_name = argv[0];

        commands = nc_hashmap_new_full(nc_string_hash, nc_string_compare, NULL, NULL);
        if (!commands) {
                DECLARE_OOM();
                return EXIT_FAILURE;
        }
        g_commands = commands;

        /* Add subcommands */
        /* Update bootloader and kernel */
        cmd_update = (SubCommand){
                .name = "update",
                .blurb = "Perform post-update configuration of the system",
                .help =
                    "Automatically install any newly discovered kernels on the file system\n\
and register them with the UEFI boot manager. Older, unused kernels will\n\
be automatically garbage collected.\n\
\n\
If necessary, the bootloader will be updated and/or installed during this\n\
time.",
                .callback = cbm_command_update,
                .usage = " [--path=/path/to/filesystem/root]",
                .requires_root = true
        };

        if (!nc_hashmap_put(commands, cmd_update.name, &cmd_update)) {
                DECLARE_OOM();
                return EXIT_FAILURE;
        }

        /* Set the timeout */
        cmd_set_timeout = (SubCommand){
                .name = "set-timeout",
                .blurb = "Set the timeout to be used by the bootloader",
                .help = "Set the default timeout to be used by" PACKAGE_NAME
                        " when using\n\
the \"update\" command.\n\
This integer value will be used when next configuring the bootloader, and is used\n\
to forcibly delay the system boot for a specified number of seconds.",
                .callback = cbm_command_set_timeout,
                .usage = " [--path=/path/to/filesystem/root]",
                .requires_root = true,
        };

        if (!nc_hashmap_put(commands, cmd_set_timeout.name, &cmd_set_timeout)) {
                DECLARE_OOM();
                return EXIT_FAILURE;
        }

        /* Get the timeout */
        cmd_get_timeout = (SubCommand){
                .name = "get-timeout",
                .blurb = "Get the timeout to be used by the bootloader",
                .help = "Get the default timeout to be used by" PACKAGE_NAME
                        " when using\n\
the \"update\" command.\n\
This integer value will be used when next configuring the bootloader, and is used\n\
to forcibly delay the system boot for a specified number of seconds.",
                .callback = cbm_command_get_timeout,
                .usage = " [--path=/path/to/filesystem/root]",
                .requires_root = true,
        };

        if (!nc_hashmap_put(commands, cmd_get_timeout.name, &cmd_get_timeout)) {
                DECLARE_OOM();
                return EXIT_FAILURE;
        }

        /* Report the system as successfully booted */
        cmd_report_booted =
            (SubCommand){.name = "report-booted",
                         .blurb = "Report the current kernel as successfully booted",
                         .help = "This command is invoked at boot to track boot success",
                         .callback = cbm_command_report_booted,
                         .requires_root = true };
        if (!nc_hashmap_put(commands, cmd_report_booted.name, &cmd_report_booted)) {
                DECLARE_OOM();
                return EXIT_FAILURE;
        }

        /* Display currently available kernels */
        cmd_list_kernels = (SubCommand){
                .name = "list-kernels",
                .blurb = "Display currently selectable kernels to boot",
                .help = "This command will show available kernels that can be used\n\
as the argument to select-kernel with a * marking the currently selected kernel.",
                .callback = cbm_command_list_kernels,
                .usage = " [--path=/path/to/filesystem/root]",
                .requires_root = true
        };

        if (!nc_hashmap_put(commands, cmd_list_kernels.name, &cmd_list_kernels)) {
                DECLARE_OOM();
                return EXIT_FAILURE;
        }

        /* Set kernel to be booted */
        cmd_set_kernel = (SubCommand){
                .name = "set-kernel",
                .blurb = "Configure kernel to be used at next boot",
                .help = "This command will set a kernel to be used as the default\n\
kernel for the next time the system boots.",
                .callback = cbm_command_set_kernel,
                .usage = " [--path=/path/to/filesystem/root]",
                .requires_root = true
        };

        if (!nc_hashmap_put(commands, cmd_set_kernel.name, &cmd_set_kernel)) {
                DECLARE_OOM();
                return EXIT_FAILURE;
        }

        /* Remove kernel */
        cmd_remove_kernel = (SubCommand){
                .name = "remove-kernel",
                .blurb = "Remove the kernel from the system",
                .help = "This command will remove a kernel from the system.",
                .callback = cbm_command_remove_kernel,
                .usage = " [--path=/path/to/filesystem/root]",
                .requires_root = true
        };

        if (!nc_hashmap_put(commands, cmd_remove_kernel.name, &cmd_remove_kernel)) {
                DECLARE_OOM();
                return EXIT_FAILURE;
        }

        /* Version */
        cmd_version = (SubCommand){
                .name = "version",
                .blurb = "Print the version and quit",
                .callback = print_version,
                .usage = NULL,
                .help = NULL,
                .requires_root = false,
        };
        if (!nc_hashmap_put(commands, cmd_version.name, &cmd_version)) {
                DECLARE_OOM();
                return EXIT_FAILURE;
        }

        /* Help */
        cmd_help = (SubCommand){.name = "help",
                                .blurb = "Show help message",
                                .callback = print_usage,
                                .usage = " [topic]",
                                .help = NULL,
                                .requires_root = false };

        if (!nc_hashmap_put(commands, cmd_help.name, &cmd_help)) {
                DECLARE_OOM();
                return EXIT_FAILURE;
        }

        if (argc < 2) {
                fprintf(stderr,
                        "Usage: %s [command]\nRe-run with -h for a list of supported commands\n",
                        binary_name);
                return EXIT_FAILURE;
        }

        /* Centralise help access */
        if (streq(argv[1], "-h") || streq(argv[1], "--help")) {
                command = cmd_help.name;
                explicit_help = true;
        } else if (streq(argv[1], "-v") || streq(argv[1], "--version")) {
                command = cmd_version.name;
        } else {
                command = argv[1];
        }

        /* discard prog name */
        ++argv;
        --argc;

        s_command = nc_hashmap_get(commands, command);
        if (!s_command) {
                fprintf(stderr, "Unknown command: %s\n", command);
                return EXIT_FAILURE;
        }

        if (!s_command->callback) {
                fprintf(stderr, "%s is not yet implemented\n", s_command->name);
                return EXIT_FAILURE;
        }

        if (s_command->requires_root && geteuid() != 0) {
                fprintf(stderr,
                        "%s \'%s\' requires root permissions to execute. Try again with sudo\n",
                        binary_name,
                        s_command->name);
                return false;
        }

        /* Invoke with discarded subcommand */
        if (!s_command->callback(--argc, ++argv)) {
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
