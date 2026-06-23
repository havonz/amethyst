#include "jailbreak.h"
#include "utils.h"
#include "trustcache.h"
#include "macho.h"
#include "dyld.h"

static void *find_dyld_symbol(const char *name, dyld_slice_t *slice) {
    struct load_command *load_cmd = slice->load_cmd;
    struct symtab_command *sym_cmd = NULL;
    uint64_t stroff = 0;
    uint64_t symoff = 0;

    for (int i = 0; i < slice->cmd_count; i++) {
        if (load_cmd->cmd == LC_SYMTAB) sym_cmd = (struct symtab_command *)load_cmd;
        load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
    }

    load_cmd = slice->load_cmd;
    for (int i = 0; i < slice->cmd_count; i++) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segment = (struct segment_command_64 *)load_cmd;
            if (strcmp(segment->segname, "__LINKEDIT") == 0) {
                if ((sym_cmd->symoff - segment->fileoff) < segment->filesize) symoff = sym_cmd->symoff;
                if ((sym_cmd->stroff - segment->fileoff) < segment->filesize) stroff = sym_cmd->stroff;
            }
            if (stroff != 0 && symoff != 0) break;
        }
        load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
    }

    struct nlist_64 *symbol = (struct nlist_64 *)(slice->hdr + symoff);
    for (int i = 0; i < sym_cmd->nsyms; i++ && symbol++) {
        uint64_t str_idx = symbol->n_un.n_strx;

        if (str_idx >= sym_cmd->strsize || str_idx == 0) continue;
        if (symbol->n_type == 115 || symbol->n_type == 17) continue;
        if (strcmp((const char *)(slice->hdr + stroff + str_idx), name) == 0) {
            if (symbol->n_value == 0) continue;
            return (void *)(slice->hdr + symbol->n_value);
        }
    }
    return NULL;
}

static void deinit_dyld_patch(dyld_patch_ctx_t *ctx) {
    if (ctx == NULL) return;
    if (ctx->file_data != NULL) munmap(ctx->file_data, ctx->file_size);
    free(ctx);
    return;
}

static dyld_patch_ctx_t *init_dyld_patch(void) {
    int fd = open("/usr/lib/dyld", O_RDONLY);
    if (fd < 0) return NULL;

    dyld_patch_ctx_t *ctx = calloc(1, sizeof(dyld_patch_ctx_t));
    ctx->file_size = (uint32_t)lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    
    ctx->vnode = vnode_for_fd(fd);
    ctx->file_data = mmap(NULL, ctx->file_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    if (ctx->file_data == MAP_FAILED) goto err;
    
    if (is_macho_fat(*(uint32_t *)ctx->file_data)) {
        bool need_swap = need_swap_macho(*(uint32_t *)ctx->file_data);
        struct fat_header fhdr = {0};
        memcpy(&fhdr, (struct fat_header *)ctx->file_data, sizeof(struct fat_header));
        if (need_swap) swap_fat_header(&fhdr, 0);
        
        for (int i = 0; i < fhdr.nfat_arch; i++) {
            size_t arch_offset = sizeof(struct fat_header) + (sizeof(struct fat_arch) * i);
            struct fat_arch arch = {0};
            memcpy(&arch, ctx->file_data + arch_offset, sizeof(struct fat_arch));
            if (need_swap) swap_fat_arch(&arch, fhdr.nfat_arch, 0);

            if (arch.cputype == CPU_TYPE_ARM64) {
                if (arch.cpusubtype == CPU_SUBTYPE_ARM64E) {
                    ctx->arm64e.offset = arch.offset;
                    ctx->arm64e.size = arch.size;
                } else {
                    ctx->arm64.offset = arch.offset;
                    ctx->arm64.size = arch.size;
                }
            }
        }
    } else {
        if (kinfo->protections.pac) {
            ctx->arm64e.offset = 0;
            ctx->arm64e.size = ctx->file_size;
        } else {
            ctx->arm64.offset = 0;
            ctx->arm64.size = ctx->file_size;
        }
    }
    
    if (ctx->arm64e.size > 0) {
        ctx->arm64e.hdr = ctx->file_data + ctx->arm64e.offset;
        ctx->arm64e.load_cmd = (struct load_command *)(ctx->arm64e.hdr64 + 1);
        ctx->arm64e.cmd_count = ctx->arm64e.hdr64->ncmds;
        ctx->arm64e.has_pac = true;

        struct load_command *load_cmd = ctx->arm64e.load_cmd;
        for (int i = 0; i < ctx->arm64e.cmd_count; i++) {
            if (load_cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *segment = (struct segment_command_64 *)load_cmd;
                if (strcmp(segment->segname, "__TEXT") == 0) {
                    struct section_64 *section = (struct section_64 *)(segment + 1);

                    for (uint32_t j = 0; j < segment->nsects; j++) {
                        if (strcmp(section[j].sectname, "__text") == 0) {
                            ctx->arm64e.text_data = (uint8_t *)ctx->arm64e.hdr + section[j].offset;
                            ctx->arm64e.text_size = (uint32_t)section[j].size;
                            break;
                        }
                    }
                    if (ctx->arm64e.text_data != NULL) break;
                }
            }
            load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
        }
    }
    
    if (ctx->arm64.size > 0) {
        ctx->arm64.hdr = ctx->file_data + ctx->arm64.offset;
        ctx->arm64.load_cmd = (struct load_command *)(ctx->arm64.hdr64 + 1);
        ctx->arm64.cmd_count = ctx->arm64.hdr64->ncmds;
        ctx->arm64.has_pac = false;

        struct load_command *load_cmd = ctx->arm64.load_cmd;
        for (int i = 0; i < ctx->arm64.cmd_count; i++) {
            if (load_cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *segment = (struct segment_command_64 *)load_cmd;
                if (strcmp(segment->segname, "__TEXT") == 0) {
                    struct section_64 *section = (struct section_64 *)(segment + 1);

                    for (uint32_t j = 0; j < segment->nsects; j++) {
                        if (strcmp(section[j].sectname, "__text") == 0) {
                            ctx->arm64.text_data = (uint8_t *)ctx->arm64.hdr + section[j].offset;
                            ctx->arm64.text_size = (uint32_t)section[j].size;
                            break;
                        }
                    }
                    if (ctx->arm64.text_data != NULL) break;
                }
            }
            load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
        }
    }
    return ctx;

err:
    deinit_dyld_patch(ctx);
    return NULL;
}

static uint8_t *bh_memmem(const uint8_t* haystack, size_t hlen, const uint8_t* needle, size_t nlen) {
    size_t last, scan = 0;
    size_t skip[256];
    
    if (nlen <= 0 || !haystack || !needle) return NULL;
    for (scan = 0; scan <= 255; scan = scan + 1) skip[scan] = nlen;

    last = nlen - 1;
    for (scan = 0; scan < last; scan = scan + 1) skip[needle[scan]] = last - scan;

    while (hlen >= nlen) {
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) return (void *)haystack;

        hlen -= skip[haystack[last]];
        haystack += skip[haystack[last]];
    }
    return NULL;
}

static int patch_amfi_flags(dyld_slice_t *slice) {
    void *symbol = find_dyld_symbol("_amfi_check_dyld_policy_self", slice);
    if (symbol == NULL) {
        uint32_t bytes[4] = {
            0xb40002e1, // cbz x1, 0x78
            0xd10103ff, // sub sp, sp, #0x40
            0xa9024ff4, // stp x20, x19, [sp, #0x20]
            0xa9037bfd  // stp x29, x30, [sp, #0x30]
        };
        
        symbol = (void *)bh_memmem(slice->text_data, slice->text_size, (uint8_t *)bytes, sizeof(bytes));
        if (symbol == NULL) {
            uint32_t bytes[6] = {
                0xd10103ff, // sub sp, sp, #0x40
                0xa9024ff4, // stp x20, x19, [sp, #0x20]
                0xa9037bfd, // stp x29, x30, [sp, #0x30]
                0x9100c3fd, // add x29, sp, #0x30
                0xaa0103f3, // mov x19, x1
                0xb40001f3  // cbz x19, 0x50
            };
            symbol = (void *)bh_memmem(slice->text_data, slice->text_size, (uint8_t *)bytes, sizeof(bytes));
            if (symbol == NULL) return -1;
        }
    }
    
    uint32_t *inst = (uint32_t *)symbol;
    inst[0] = 0xd28007e8; // mov x8, #0x3f
    inst[1] = 0xf9000028; // str x8, [x1]
    inst[2] = 0xaa1f03e0; // mov x0, xzr
    inst[3] = 0xd65f03c0; // ret
    return 0;
}

static uint32_t get_hash_rank(const CS_CodeDirectory *cd) {
    switch (cd->hashType) {
        case CS_HASHTYPE_SHA1: return 1;
        case CS_HASHTYPE_SHA256_TRUNCATED: return 2;
        case CS_HASHTYPE_SHA256: return 3;
        case CS_HASHTYPE_SHA384: return 4;
        default: return 0;
    }
}

static uint8_t *get_cd_hash(CS_CodeDirectory *cd) {
    uint32_t size = ntohl(cd->length);
    uint8_t *hash = calloc(1, CS_CDHASH_LEN);
    
    switch (cd->hashType) {
        case CS_HASHTYPE_SHA1: CC_SHA1(cd, size, hash); break;
        case CS_HASHTYPE_SHA256:
        case CS_HASHTYPE_SHA256_TRUNCATED: CC_SHA256(cd, size, hash); break;
        case CS_HASHTYPE_SHA384: CC_SHA384(cd, size, hash); break;
        default: return NULL;
    }
    return hash;
}

static int resign_dyld(dyld_slice_t *slice) {
    struct load_command *load_cmd = slice->load_cmd;
    struct linkedit_data_command *linkedit = NULL;

    for (int i = 0; i < slice->cmd_count; i++) {
        if (load_cmd->cmd == LC_CODE_SIGNATURE) {
            linkedit = (struct linkedit_data_command *)load_cmd;
            break;
        }
        load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
    }
    
    if (linkedit == NULL) return -1;
    CS_SuperBlob *super_blob = (CS_SuperBlob *)(slice->hdr + linkedit->dataoff);
    uint8_t *current_hash = NULL;
    uint32_t best_rank = 0;
    CS_CodeDirectory *best_cd = NULL;
    
    for (int i = 0; i < ntohl(super_blob->count); i++) {
        const CS_BlobIndex *index = &super_blob->index[i];
        uint32_t type = ntohl(index->type);
        uint32_t offset = ntohl(index->offset);
        if (ntohl(super_blob->length) < offset) break;
        
        CS_CodeDirectory *sub = (CS_CodeDirectory *)((uint64_t)super_blob + offset);
        if (type == CSSLOT_CODEDIRECTORY ||
            (type >= CSSLOT_ALTERNATE_CODEDIRECTORIES &&
             type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
            
            uint32_t rank = get_hash_rank(sub);
            if (rank > best_rank) {
                if (current_hash != NULL) free(current_hash);
                current_hash = get_cd_hash(sub);
                best_rank = rank;
                best_cd = sub;
            }
        }
    }
    
    if (best_cd == NULL) return -1;
    int slot_count = (int)ntohl(best_cd->nCodeSlots);
    uint32_t page_size = (uint32_t)(pow(2.0, (double)(best_cd->pageSize)));
    
    for (int i = 0; i < slot_count; i++) {
        uint8_t *expected_hash = (uint8_t *)best_cd + ntohl(best_cd->hashOffset) + (i * best_cd->hashSize);
        uint8_t real_hash[best_cd->hashSize];
        bzero(real_hash, best_cd->hashSize);
        
        uint64_t page_offset = (uint64_t)(i * page_size);
        uint8_t *page = (uint8_t *)(slice->hdr + page_offset);
        uint32_t calc_size = page_size;
        if (i == ntohl(best_cd->nCodeSlots) - 1) {
            calc_size = ntohl(best_cd->codeLimit) - (uint32_t)page_offset;
        }
        
        switch (best_cd->hashType) {
            case CS_HASHTYPE_SHA1: CC_SHA1(page, calc_size, real_hash); break;
            case CS_HASHTYPE_SHA256:
            case CS_HASHTYPE_SHA256_TRUNCATED: CC_SHA256(page, calc_size, real_hash); break;
            case CS_HASHTYPE_SHA384: CC_SHA384(page, calc_size, real_hash); break;
            default: break;
        }
        
        if (memcmp(expected_hash, real_hash, best_cd->hashSize) != 0) {
            memcpy(expected_hash, real_hash, best_cd->hashSize);
        }
    }
    
    uint8_t new_cd_hash[best_cd->hashSize];
    if (current_hash != NULL) free(current_hash);
    
    switch (best_cd->hashType) {
        case CS_HASHTYPE_SHA1: CC_SHA1(best_cd, ntohl(best_cd->length), new_cd_hash); break;
        case CS_HASHTYPE_SHA256:
        case CS_HASHTYPE_SHA256_TRUNCATED: CC_SHA256(best_cd, ntohl(best_cd->length), new_cd_hash); break;
        case CS_HASHTYPE_SHA384: CC_SHA384(best_cd, ntohl(best_cd->length), new_cd_hash); break;
        default: return -1;
    }
    
    trustcache_add_hash(new_cd_hash, best_cd->hashType);
    return 0;
}

int patch_dyld(void) {
    char test_path[PATH_MAX] = {0};
    realpath("/usr/lib/dyld", test_path);
    if (strcmp(test_path, "/usr/lib/dyld_patch") == 0) return 0;

    dyld_patch_ctx_t *ctx = init_dyld_patch();
    if (ctx->arm64.size > 0) {
        patch_amfi_flags(&ctx->arm64);
        resign_dyld(&ctx->arm64);
    }

    if (ctx->arm64e.size > 0) {
        patch_amfi_flags(&ctx->arm64e);
        resign_dyld(&ctx->arm64e);
    }

    FILE *file = fopen("/amethyst/dyld_patch", "wb+");
    fwrite((void *)ctx->file_data, ctx->file_size, 1, file);
    fflush(file);
    fclose(file);
    sync();

    copy_file("/amethyst/dyld_patch", "/usr/lib/dyld_patch");
    swap_namecache_vnode("/usr/lib/dyld_patch", "/usr/lib/dyld");
    chmod("/usr/lib/dyld_patch", 0755);
    chown("/usr/lib/dyld_patch", 0, 0);
    return 0;
}
