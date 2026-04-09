/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "resolver.h"
#include "devices_table.h"

#include <stdio.h>
#include <string.h>

/* Forward declarations for strategy functions — these are implemented in
 * the strategies subdirectory .c files created in Phase 3. Kept here so resolver.c can
 * populate g_value_specs[] with the right function pointers. */
extern resolved_t strategy_cli_override(value_id_t, resolve_ctx_t *);
extern resolved_t strategy_probe_procfs(value_id_t, resolve_ctx_t *);
extern resolved_t strategy_probe_loaded_module(value_id_t, resolve_ctx_t *);
extern resolved_t strategy_probe_ondisk_module(value_id_t, resolve_ctx_t *);
extern resolved_t strategy_probe_disasm(value_id_t, resolve_ctx_t *);
extern resolved_t strategy_probe_binary_search(value_id_t, resolve_ctx_t *);
extern resolved_t strategy_config_explicit(value_id_t, resolve_ctx_t *);
extern resolved_t strategy_config_automatch(value_id_t, resolve_ctx_t *);
extern resolved_t strategy_config_fuzzy(value_id_t, resolve_ctx_t *);

#define CLI  { strategy_cli_override,       "cli_override"       }
#define PL   { strategy_probe_loaded_module,"probe_loaded_module"}
#define PO   { strategy_probe_ondisk_module,"probe_ondisk_module"}
#define PP   { strategy_probe_procfs,       "probe_procfs"       }
#define PD   { strategy_probe_disasm,       "probe_disasm"       }
#define PB   { strategy_probe_binary_search,"probe_binary_search"}
#define CE   { strategy_config_explicit,    "config_explicit"    }
#define CA   { strategy_config_automatch,   "config_automatch"   }
#define CF   { strategy_config_fuzzy,       "config_fuzzy"       }
#define END  { 0, 0 }

#ifdef KH_RESOLVER_DEFINE_SPECS
const value_spec_t g_value_specs[VAL__COUNT] = {
    { VAL_MODULE_LAYOUT_CRC, "module_layout_crc",
        { CLI, PL, PO, CE, CA, CF, END } },
    { VAL_PRINTK_CRC, "_printk_crc",
        { CLI, PL, PO, CE, CA, CF, END } },
    { VAL_MEMCPY_CRC, "memcpy_crc",
        { CLI, PL, PO, CE, CA, CF, END } },
    { VAL_MEMSET_CRC, "memset_crc",
        { CLI, PL, PO, CE, CA, CF, END } },
    { VAL_VERMAGIC, "vermagic",
        { CLI, PL, PP, CE, CA, CF, END } },
    /* Config entries come before kernel-level probes (probe_disasm/
     * probe_binary_search) for struct_module values. Rationale: the old
     * resolve_offsets() in kmod_loader.c consulted the preset table (now
     * migrated to kmod/devices/conf) BEFORE running the /proc/kcore
     * disassembly or the binary-probe loop. Running those probes on
     * kernels that already have a verified config entry is both wasteful
     * and unsafe (probe_binary_search crashes on some AVDs). Keep PO
     * (vendor .ko introspection) first because it's the most accurate
     * source on real devices. */
    { VAL_THIS_MODULE_SIZE, "this_module_size",
        { CLI, PO, CE, CA, CF, PD, END } },
    { VAL_MODULE_INIT_OFFSET, "module_init_offset",
        { CLI, PO, CE, CA, CF, PD, PB, END } },
    { VAL_MODULE_EXIT_OFFSET, "module_exit_offset",
        { CLI, PO, CE, CA, CF, PD, END } },
    { VAL_KALLSYMS_LOOKUP_NAME_ADDR, "kallsyms_lookup_name_addr",
        { CLI, PP, END } },
};
#endif /* KH_RESOLVER_DEFINE_SPECS */

const char *value_name(value_id_t id)
{
    if (id < 0 || id >= VAL__COUNT) return "(invalid)";
    return g_value_specs[id].display_name;
}

resolved_t resolve(value_id_t id, resolve_ctx_t *ctx, trace_entry_t *trace_out)
{
    resolved_t out = { .available = 0 };
    const value_spec_t *spec = &g_value_specs[id];
    trace_entry_t trace = { .id = id, .display_name = spec->display_name, .ok = 0 };

    for (int i = 0; spec->chain[i].fn != NULL; i++) {
        /* Honor --no-probe / --no-config flags */
        const char *name = spec->chain[i].name;
        if (ctx->no_probe && strncmp(name, "probe_", 6) == 0) continue;
        if (ctx->no_config && strncmp(name, "config_", 7) == 0) continue;

        /* Record the attempt */
        if (trace.tried_count < KH_TRACE_MAX) {
            strncpy(trace.tried[trace.tried_count], name, sizeof(trace.tried[0]) - 1);
            trace.tried_count++;
        }

        out = spec->chain[i].fn(id, ctx);
        if (out.available) {
            trace.final = out;
            trace.ok = 1;
            break;
        }
    }

    if (trace_out) *trace_out = trace;
    return out;
}

void trace_dump(const trace_entry_t *trace, int count)
{
    fprintf(stderr, "Resolution trace:\n");
    for (int i = 0; i < count; i++) {
        const trace_entry_t *t = &trace[i];
        fprintf(stderr, "  %-28s = ", t->display_name);
        if (t->ok) {
            if (t->final.str_val[0])
                fprintf(stderr, "%s", t->final.str_val);
            else
                fprintf(stderr, "0x%llx", (unsigned long long)t->final.u64_val);
            fprintf(stderr, "   [%s]\n", t->final.source_label);
        } else {
            fprintf(stderr, "UNRESOLVED (tried:");
            for (int j = 0; j < t->tried_count; j++)
                fprintf(stderr, " %s", t->tried[j]);
            fprintf(stderr, ")\n");
        }
    }
}
