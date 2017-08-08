#include <endian.h>
/* Workaround for using --std=c11 in CBM. Provide "relaxed" defines which efivar
 * expects. */
#define BYTE_ORDER      __BYTE_ORDER
#define LITTLE_ENDIAN   __LITTLE_ENDIAN
#define BIG_ENDIAN      __BIG_ENDIAN
#include <ctype.h>
#include <efivar.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <alloca.h>

typedef struct boot_rec boot_rec_t;

struct boot_rec {
    char *name;
    int num;
    unsigned char *data;
    boot_rec_t *next;
};

static boot_rec_t *boot_recs;
static int boot_recs_cnt;

static void free_boot_recs(void) {
    boot_rec_t *p, *c;
    c = boot_recs;
    if (!c) return;
    do {
        p = c;
        c = c->next;
        free(p);
    } while (c);
}

static void print_boot_recs(void) {
    boot_rec_t *c = boot_recs;
    if (!c) return;
    do {
        fprintf(stderr, "Boot record #%d: %s\n", c->num, c->name);
    } while ((c = c->next));
}

static int read_boot_recs(void) {
    int res;
    efi_guid_t *guid = NULL;
    char *name = NULL;
    boot_rec_t *p, *c;
    int i = 0;

    while ((res = efi_get_next_variable_name(&guid, &name)) > 0) {
        char *num_end;
        if (strncmp(name, "Boot", 4)) continue;
        if (!isxdigit(name[4]) || !isxdigit(name[5]) || !isxdigit(name[6])
                || !isxdigit(name[7])) continue;
        if (memcmp(guid, &efi_guid_global, sizeof(efi_guid_t))) continue;

        c = (boot_rec_t *)malloc(sizeof(boot_rec_t));
        memset(c, 0, sizeof(boot_rec_t));
        c->name = strdup(name);
        c->num = (int)strtol(name + 4, &num_end, 16);
        if (num_end - name - 4 != 4) continue;

        if (!boot_recs) {
            boot_recs = p = c;
        } else {
            p->next = c;
            p = c;
        }
        i++;
    }
    boot_recs_cnt = i;
    print_boot_recs();
    return 0;
}

static int cmp(const void *a, const void *b) {
    return *((int *)a) - *((int *)b);
}

static int find_free_boot_rec(void) {
    int *nums;
    int res;
    int i = 0;
    boot_rec_t *c = boot_recs;
    size_t cnt;

    if (!boot_recs) return -1;
    if (boot_recs_cnt < 1) return 0;

    cnt = (size_t)boot_recs_cnt;

    nums = (int *)alloca(sizeof(int) * cnt); 
    memset(nums, 0, sizeof(int) * cnt);

    do {
        nums[i] = c->num;
        i++;
    } while ((c = c->next));

    qsort(nums, cnt, sizeof(int), cmp);

    for (i = 0, res = 0; i < boot_recs_cnt; i++, res++) {
        if (res < nums[i]) break;
    }
    if (res == nums[boot_recs_cnt - 1]) res++;
    fprintf(stderr, "Found: %d\n", res);
    return res;
}

int efi_create_boot_rec(void) {
    int slot = find_free_boot_rec();

    if (slot < 0) return -1;

    return 0;
}

int efi_init(void) {
    if (efi_variables_supported() < 0) return -1;
    if (read_boot_recs() < 0) return -1;
    return 0;
}

/* vim: set nosi noai cin ts=4 sw=4 et tw=80: */
