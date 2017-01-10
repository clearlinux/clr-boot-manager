/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2017 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#pragma once

#define _GNU_SOURCE

#include <stdbool.h>

/**
 * Parse all user & cmdline files within the root prefix, and merge them
 * into a single cmdline "entry".
 * This is then combined with the final cmdline in the bootloaders
 * to allow local overrides and additions.
 *
 * The file may contain new lines, which are skipped. Additionally, the '#'
 * character is treated as a comment and will also be skipped.
 */
char *cbm_parse_cmdline_files(const char *root);

/**
 * Parse a single cmdline, named cmdline file fully.
 */
char *cbm_parse_cmdline_file(const char *file);

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
