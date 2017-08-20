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

int efi_init(void);
void efi_destroy(void);
int efi_create_boot_rec(const char *, const char *);

/* vim: set nosi noai cin ts=4 sw=4 et tw=80: */
