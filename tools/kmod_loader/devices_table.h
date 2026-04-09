/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KH_DEVICES_TABLE_H_
#define _KH_DEVICES_TABLE_H_

#include <stddef.h>
#include <stdint.h>

struct device_entry {
    const char *name;
    const char *description;
    const char *arch;
    const char *match_kernelrelease; /* prefix match on uname -r */
    uint32_t    module_layout_crc;
    uint32_t    printk_crc;
    uint32_t    memcpy_crc;
    uint32_t    memset_crc;
    uint32_t    this_module_size;
    uint32_t    module_init_offset;
    uint32_t    module_exit_offset;
    const char *vermagic;
    int         verified;
};

/* Null-sentinel terminated (entry with .name == NULL). */
extern const struct device_entry g_devices[];
extern const size_t g_devices_count;

#endif /* _KH_DEVICES_TABLE_H_ */
