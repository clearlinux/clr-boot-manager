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

#define _GNU_SOURCE

#include "bootvar.h"

#include <endian.h>
/* Workaround for using --std=c11 in CBM. Provide "relaxed" defines which efivar
 * expects. */
#define BYTE_ORDER __BYTE_ORDER
#define LITTLE_ENDIAN __LITTLE_ENDIAN
#define BIG_ENDIAN __BIG_ENDIAN

#include <alloca.h>
#include <blkid.h>
#include <ctype.h>
#include <efiboot.h>
#include <efi.h>
#include <efilib.h>
#include <efivar.h>
#include <errno.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>

/* 1K is the limit for boot var storage that efivar defines. it should be
 * enough. actual space occupied is normally >2 times less. */
#define BOOT_VAR_MAX 1024

typedef struct boot_rec boot_rec_t;

struct boot_rec {
        char *name;
        int num;
        unsigned char *data;
        boot_rec_t *next;
};

static boot_rec_t *boot_recs;
static int boot_recs_cnt;

static void bootvar_free_boot_recs(void)
{
        boot_rec_t *p, *c;
        c = boot_recs;
        if (!c)
                return;
        boot_recs = NULL;
        do {
                p = c;
                c = c->next;
                free(p);
        } while (c);
}

static void bootvar_print_boot_recs(void) __attribute__((unused));
static void bootvar_print_boot_recs(void)
{
        boot_rec_t *c = boot_recs;
        if (!c)
                return;
        do {
                fprintf(stderr, "Boot record #%d: %s\n", c->num, c->name);
        } while ((c = c->next));
}

/* enumerates boot recs and initializes boot_recs and boot_recs_cnt. */
static int bootvar_read_boot_recs(void)
{
        int res;
        efi_guid_t *guid = NULL;
        char *name = NULL;
        boot_rec_t *p = NULL, *c;
        int i = 0;

        bootvar_free_boot_recs();

        while ((res = efi_get_next_variable_name(&guid, &name)) > 0) {
                char *num_end;
                if (strncmp(name, "Boot", 4))
                        continue;
                if (!isxdigit(name[4]) || !isxdigit(name[5]) || !isxdigit(name[6]) ||
                    !isxdigit(name[7]))
                        continue;
                if (memcmp(guid, &efi_guid_global, sizeof(efi_guid_t)))
                        continue;

                c = (boot_rec_t *)malloc(sizeof(boot_rec_t));
                memset(c, 0, sizeof(boot_rec_t));
                c->name = strdup(name);
                c->num = (int)strtol(name + 4, &num_end, 16);
                if (num_end - name - 4 != 4)
                        continue;

                if (!boot_recs) {
                        boot_recs = p = c;
                } else {
                        p->next = c;
                        p = c;
                }
                i++;
        }
        if (res < 0) {
                LOG_FATAL("efi_get_next_variable_name() failed: %s", strerror(errno));
                return -EBOOT_VAR_ERR;
        }
        boot_recs_cnt = i;
        return 0;
}

/* given the record, puts it first in the boot order (via BootOrder EFI
 * variable). */
static int bootvar_push_to_boot_order(boot_rec_t *rec)
{
        uint16_t number;
        uint16_t *boot_order;
        uint16_t *new_boot_order;
        size_t boot_order_size;
        size_t new_boot_order_size;
        uint32_t boot_order_attrs;
        unsigned int i;
        int found = 0;

        if (!rec || !rec->name)
                return -EBOOT_VAR_ERR;

        if (efi_get_variable(EFI_GLOBAL_GUID,
                             "BootOrder",
                             (uint8_t **)&boot_order,
                             &boot_order_size,
                             &boot_order_attrs)) {
                LOG_FATAL("efi_get_variable() failed: %s", strerror(errno));
                return -EBOOT_VAR_ERR;
        }

        sscanf(rec->name, "Boot%04hX", &number);

        /* read as uint16_t, hence twice less the returned size */
        boot_order_size >>= 1;

        for (i = 0; i < boot_order_size; i++) {
                if (boot_order[i] == number) {
                        found = 1;
                        break;
                }
        }

        if (!found) {
                new_boot_order_size = boot_order_size + 1;
                new_boot_order = (uint16_t *)malloc(new_boot_order_size * sizeof(uint16_t));
                new_boot_order[0] = number;
                memcpy(new_boot_order + 1, boot_order, boot_order_size * sizeof(uint16_t));
        } else {
                uint16_t *c;
                new_boot_order = (uint16_t *)malloc(boot_order_size * sizeof(uint16_t));
                new_boot_order[0] = number;
                c = new_boot_order + 1;
                for (i = 0; i < boot_order_size; i++) {
                        if (boot_order[i] != number) {
                                *c = boot_order[i];
                                c++;
                        }
                }
                new_boot_order_size = (size_t)(c - new_boot_order);
        }

        new_boot_order_size <<= 1;
        if (efi_set_variable(EFI_GLOBAL_GUID,
                             "BootOrder",
                             (uint8_t *)new_boot_order,
                             new_boot_order_size,
                             boot_order_attrs,
                             0644)) {
                LOG_FATAL("efi_set_variable() failed: %s", strerror(errno));
                return -EBOOT_VAR_ERR;
        }

        return 0;
}

static int cmp(const void *a, const void *b)
{
        return *((int *)a) - *((int *)b);
}

/* finds the first available free number for a boot var. */
static int bootvar_find_free_no(void)
{
        int *nums;
        int res;
        int i = 0;
        boot_rec_t *c = boot_recs;
        size_t cnt;

        if (!boot_recs)
                return -1;
        if (!boot_recs_cnt)
                return 0; /* no records. */

        cnt = (size_t)boot_recs_cnt;

        nums = (int *)alloca(sizeof(int) * cnt);
        memset(nums, 0, sizeof(int) * cnt);

        do {
                nums[i] = c->num;
                i++;
        } while ((c = c->next));

        qsort(nums, cnt, sizeof(int), cmp);

        for (i = 0, res = 0; i < boot_recs_cnt; i++, res++) {
                if (res < nums[i])
                        break;
        }
        if (res == nums[boot_recs_cnt - 1])
                res++; /* no gap. */
        return res;
}

/* finds and returns boot rec whose value is data of size. NULL if not found. */
static boot_rec_t *bootvar_find_boot_rec(uint8_t *data, size_t size)
{
        boot_rec_t *c = boot_recs;
        boot_rec_t *res = NULL;

        uint8_t *cdata;
        size_t csize;
        uint32_t cattr;

        if (!boot_recs || !boot_recs_cnt)
                return NULL;

        do {
                if (efi_get_variable(EFI_GLOBAL_GUID, c->name, &cdata, &csize, &cattr) < 0) {
                        LOG_ERROR("efi_get_variable() failed: %s", strerror(errno));
                        continue;
                }
                if (csize == size && !memcmp(cdata, data, csize)) {
                        res = c;
                        break;
                }
        } while ((c = c->next));

        return res;
}

typedef struct part_info {
        char disk_path[PATH_MAX];
        int part_no;
        char part_type[36 + 1]; /* GUID string, hyphen notation */
} part_info_t;

/* given the location of the ESP mount point, returns the partition information
 * needed to create boot variable which points to that bootloader. */
static int bootvar_get_part_info(const char *path, part_info_t *pi)
{
        blkid_probe probe;
        blkid_partition part;
        blkid_partlist parts;
        struct stat st;
        dev_t disk_dev;
        char disk_path[PATH_MAX];
        const char *part_type;

        if (stat(path, &st)) {
                LOG_FATAL("stat() failed on %s: %s", path, strerror(errno));
                return -EBOOT_VAR_ERR;
        }

        strcpy(disk_path, "/dev/");
        if (blkid_devno_to_wholedisk(st.st_dev, disk_path + 5, PATH_MAX - 5, &disk_dev)) {
                LOG_FATAL("blkid_devno_to_wholedisk() error");
                return -EBOOT_VAR_ERR;
        }

        if (!(probe = blkid_new_probe_from_filename(disk_path))) {
                LOG_FATAL("blkid_new_probe_from_filename() error");
                return -EBOOT_VAR_ERR;
        }

        if (blkid_probe_enable_partitions(probe, 1)) {
                LOG_FATAL("blkid_probe_enable_partitions() error");
                return -EBOOT_VAR_ERR;
        }

        if (!(parts = blkid_probe_get_partitions(probe))) {
                LOG_FATAL("blkid_probe_get_partitions() error");
                return -EBOOT_VAR_ERR;
        }

        if (!(part = blkid_partlist_devno_to_partition(parts, st.st_dev))) {
                LOG_FATAL("blkid_partlist_devno_to_partition() error");
                return -EBOOT_VAR_ERR;
        }

        if ((pi->part_no = blkid_partition_get_partno(part)) < 0) {
                LOG_FATAL("blkid_partition_get_partno() error");
                return -EBOOT_VAR_ERR;
        }

        part_type = blkid_partition_get_type_string(part);
        if (!part_type) {
                LOG_FATAL("blkid_partition_get_type_string() returned NULL");
                return -EBOOT_VAR_ERR;
        } else if (strlen(part_type) != 36) {
                LOG_FATAL("partition type does not seem to be a GUID: %s", part_type);
                return -EBOOT_VAR_ERR;
        }

        snprintf(pi->disk_path, strlen(disk_path) + 1, "%s", disk_path);
        snprintf(pi->part_type, 36 + 1, "%s", part_type);

        blkid_free_probe(probe);

        return 0;
}

/* attempts to look up existing record, otherwise creates a new one. */
static boot_rec_t *bootvar_add_boot_rec(uint8_t *data, size_t len)
{
        char name[9]; /* variable name, e.g. "BootXXXX". */
        int slot;
        uint32_t attr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                        EFI_VARIABLE_RUNTIME_ACCESS;
        boot_rec_t *c, *res = bootvar_find_boot_rec(data, len);

        if (res)
                return res;
        /* no such record, create one. */
        slot = bootvar_find_free_no();
        if (slot < 0)
                return NULL;
        if (snprintf(name, 9, "Boot%04X", slot) > 8)
                return NULL;
        if (efi_set_variable(EFI_GLOBAL_GUID, name, data, len, attr, 0644) < 0) {
                LOG_FATAL("efi_set_variable() failed: %s", strerror(errno));
                return NULL;
        }
        /* re-read the records and find the variable that was just created. */
        if (bootvar_read_boot_recs() < 0)
                return NULL;
        if (!boot_recs)
                return NULL; /* something went terribly wrong. */
        c = boot_recs;
        do {
                if (!strcmp(c->name, name)) {
                        res = c;
                        break;
                }
        } while ((c = c->next));

        return res;
}

int bootvar_create(const char *esp_mount_path, const char *bootloader_esp_path, char *varname,
                   size_t size)
{
        part_info_t pi;
        uint8_t fdev_path[PATH_MAX];
        uint8_t data[BOOT_VAR_MAX]; /* this is what efivar supports and it should be
                                       enough. */
        long int len;
        boot_rec_t *rec;

        if (bootvar_get_part_info(esp_mount_path, &pi))
                return -1;

        len = efi_generate_file_device_path_from_esp(fdev_path,
                                                     PATH_MAX,
                                                     pi.disk_path,
                                                     pi.part_no,
                                                     bootloader_esp_path,
                                                     EFIBOOT_ABBREV_HD);
        if (len < 0) {
                LOG_FATAL("efi_generate_file_device_path_from_esp() failed: %s", strerror(errno));
                return -EBOOT_VAR_ERR;
        }

        len = efi_loadopt_create(data,
                                 BOOT_VAR_MAX,
                                 LOAD_OPTION_ACTIVE,
                                 (void *)fdev_path,
                                 len,
                                 (unsigned char *)"Linux bootloader",
                                 NULL,
                                 0);
        if (len < 0) {
                LOG_FATAL("efi_loadopt_create() failed: %s", strerror(errno));
                return -EBOOT_VAR_ERR;
        }

        rec = bootvar_add_boot_rec(data, (size_t)len);
        if (!rec)
                return -EBOOT_VAR_ERR;

        if (bootvar_push_to_boot_order(rec))
                return -EBOOT_VAR_ERR;

        if (varname && size) {
                size_t len = strlen(rec->name);
                if (len < size) {
                        snprintf(varname, len + 1, "%s", rec->name);
                } else {
                        LOG_ERROR("%lu bytes is not enough. Need %lu.", size, len);
                }
        }

        return 0;
}

int bootvar_init(void)
{
        if (efi_variables_supported() < 0)
                return -EBOOT_VAR_NOSUP;
        if (bootvar_read_boot_recs() < 0)
                return -EBOOT_VAR_ERR;
        return 0;
}

void bootvar_destroy(void)
{
        bootvar_free_boot_recs();
}

/* vim: set nosi noai cin ts=8 sw=8 et tw=80: */
