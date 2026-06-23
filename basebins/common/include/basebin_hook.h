#ifndef basebin_hook_h
#define basebin_hook_h

#include "basebin_common.h"
#include "basebin_instructions.h"

typedef enum {
    HOOK_TYPE_NONE = -1,
    HOOK_TYPE_DIRECT_BRANCH,
    HOOK_TYPE_DIRECT_BRANCH_TRAMPOLINE,
    HOOK_TYPE_ADRP_BR,
    HOOK_TYPE_ADRP_BR_TRAMPOLINE,
    HOOK_TYPE_ADRP_ADD_BR,
    HOOK_TYPE_LDR_BR,
    HOOK_TYPE_MOV2_BR,
    HOOK_TYPE_ALT_MOV2_BR,
    HOOK_TYPE_MOV3_BR,
    HOOK_TYPE_MOV4_BR,
    HOOK_TYPE_DYNAMIC_INTERPOSE
} hook_type_t;

typedef struct {
    hook_type_t type;
    uint32_t size;
    bool requires_relocation;
} hook_info_t;

typedef struct __interpose_entry {
    struct __interpose_entry *next;
    void *target;
    void *replacement;
} interpose_entry_t;

typedef struct {
    volatile interpose_entry_t *first_entry;
    volatile interpose_entry_t *last_entry;
    volatile bool callback_set;
} interpose_info_t;

typedef struct {
	void *replacement;
	void *target;
} dyld_interpose_tuple_t;

extern void dyld_dynamic_interpose(struct mach_header *hdr, dyld_interpose_tuple_t *array, size_t count);

int interpose_function(void *target, void *replacement, void **original);
int hook_function(void *target, void *replacement, void **original);

#endif /* basebin_hook_h */
