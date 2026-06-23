#ifndef dyld_h
#define dyld_h

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/swap.h>
#include <mach-o/dyld.h>

typedef struct {
    union {
        struct mach_header_64 *hdr64;
        uint8_t *hdr;
    };
    struct load_command *load_cmd;
    uint32_t cmd_count;
    uint32_t offset;
    uint32_t size;
    uint8_t *text_data;
    uint32_t text_size;
    bool has_pac;
} dyld_slice_t;

typedef struct {
    uint8_t *file_data;
    uint32_t file_size;
    uint64_t vnode;
    dyld_slice_t arm64;
    dyld_slice_t arm64e;
} dyld_patch_ctx_t;

int patch_dyld(void);

#endif /* dyld_h */
