#include "basebin_util.h"
#include "basebin_macho.h"

void macho_release(macho_ctx_t *ctx) {
    if (ctx == NULL) return;
    if (ctx->slice_list != NULL) free(ctx->slice_list);
    if (ctx->file_data != NULL) munmap(ctx->file_data, ctx->file_size);
    if (ctx->path != NULL) free(ctx->path);
    free(ctx);
}

static bool macho_supported(cpu_type_t cpu_type, cpu_subtype_t cpu_subtype, uint32_t file_type) {
    if (cpu_type != CPU_TYPE_ARM64) return false;
    if (cpu_subtype == CPU_SUBTYPE_ARM64_V8 || cpu_subtype == CPU_SUBTYPE_ARM64_ALL) return true;
    
    if (soc_is_arm64e()) {
        if (cpu_subtype == CPU_SUBTYPE_ARM64E) return true;
        if (cpu_subtype == (CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_PTRAUTH_ABI)) {
            if (file_type == MH_DYLIB || file_type == MH_BUNDLE) return true;
        }
    }
    return false;
}

macho_ctx_t *macho_load(const char *path) {
    if (path == NULL || path[0] == '\0') return NULL;
    macho_ctx_t *ctx = NULL;
    int fd = -1;
    
    if ((fd = open(path, O_RDONLY)) < 0) goto err;
    if ((ctx = calloc(1, sizeof(macho_ctx_t))) == NULL) goto err;
    if ((ctx->file_size = (uint32_t)lseek(fd, 0, SEEK_END)) < sizeof(struct mach_header)) goto err;
    lseek(fd, 0, SEEK_SET);
    
    if ((ctx->file_data = mmap(NULL, ctx->file_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED) goto err;
    close(fd);
    fd = -1;
    
    uint32_t magic = *(uint32_t *)ctx->file_data;
    if (!MACHO_VALID(magic)) goto err;
    bool need_swap = MACHO_REQUIRES_SWAP(magic);
    
    if (MACHO_FAT(magic)) {
        struct fat_header *fhdr = (struct fat_header *)ctx->file_data;
        if (need_swap) swap_fat_header(fhdr, 0);
        
        ctx->slice_list = calloc(1, sizeof(macho_slice_t) * (fhdr->nfat_arch + 1));
        if (ctx->slice_list == NULL) goto err;
        ctx->slice_count = 0;

        for (uint32_t i = 0; i < fhdr->nfat_arch; i++) {
            size_t arch_offset = sizeof(struct fat_header) + (sizeof(struct fat_arch) * i);
            struct fat_arch *arch = (struct fat_arch *)(ctx->file_data + arch_offset);
            if (need_swap) swap_fat_arch(arch, 1, 0);

            uint32_t file_type = -1;
            if (MACHO_32BIT(*(uint32_t *)(ctx->file_data + arch->offset))) {
                struct mach_header hdr = {0};
                memcpy(&hdr, ctx->file_data + arch->offset, sizeof(struct mach_header));
                if (MACHO_REQUIRES_SWAP(hdr.magic)) swap_mach_header(&hdr, 0);
                file_type = hdr.filetype;
            } else {
                struct mach_header_64 hdr = {0};
                memcpy(&hdr, ctx->file_data + arch->offset, sizeof(struct mach_header_64));
                if (MACHO_REQUIRES_SWAP(hdr.magic)) swap_mach_header_64(&hdr, 0);
                file_type = hdr.filetype;
            }
            
            if (macho_supported(arch->cputype, arch->cpusubtype, file_type)) {
                ctx->slice_list[ctx->slice_count].cpu_type = arch->cputype;
                ctx->slice_list[ctx->slice_count].cpu_subtype = arch->cpusubtype;
                ctx->slice_list[ctx->slice_count].offset = arch->offset;
                ctx->slice_list[ctx->slice_count].size = arch->size;
                ctx->slice_list[ctx->slice_count].file_data = ctx->file_data;
                ctx->slice_list[ctx->slice_count].file_size = ctx->file_size;
                
                ctx->slice_list[ctx->slice_count].hdr = ctx->file_data + arch->offset;
                ctx->slice_list[ctx->slice_count].is_32bit = MACHO_32BIT(ctx->slice_list[ctx->slice_count].hdr32->magic);
                ctx->slice_list[ctx->slice_count].has_ptrauth = ((arch->cputype == CPU_TYPE_ARM64) && (arch->cpusubtype & CPU_SUBTYPE_ARM64E) != 0);
                
                if (MACHO_REQUIRES_SWAP(ctx->slice_list[ctx->slice_count].hdr32->magic)) {
                    if (ctx->slice_list[ctx->slice_count].is_32bit) swap_mach_header(ctx->slice_list[ctx->slice_count].hdr32, 0);
                    else swap_mach_header_64(ctx->slice_list[ctx->slice_count].hdr64, 0);
                }
                
                if (ctx->slice_list[ctx->slice_count].is_32bit) {
                    ctx->slice_list[ctx->slice_count].load_cmd = (struct load_command *)(ctx->slice_list[ctx->slice_count].hdr32 + 1);
                    ctx->slice_list[ctx->slice_count].cmd_count = ctx->slice_list[ctx->slice_count].hdr32->ncmds;
                } else {
                    ctx->slice_list[ctx->slice_count].load_cmd = (struct load_command *)(ctx->slice_list[ctx->slice_count].hdr64 + 1);
                    ctx->slice_list[ctx->slice_count].cmd_count = ctx->slice_list[ctx->slice_count].hdr64->ncmds;
                }
                ctx->slice_count++;
            }
        }
        if (ctx->slice_count == 0) goto err;
    } else {
        ctx->slice_list = calloc(1, sizeof(macho_slice_t) * 2);
        if (ctx->slice_list == NULL) goto err;
        ctx->slice_count = 0;
        
        uint32_t file_type = -1;
        cpu_type_t cpu_type = -1;
        cpu_subtype_t cpu_subtype = -1;
        
        if (MACHO_32BIT(*(uint32_t *)ctx->file_data)) {
            if (MACHO_REQUIRES_SWAP(*(uint32_t *)ctx->file_data)) swap_mach_header((struct mach_header *)ctx->file_data, 0);
            file_type = ((struct mach_header *)ctx->file_data)->filetype;
            cpu_type = ((struct mach_header *)ctx->file_data)->cputype;
            cpu_subtype = ((struct mach_header *)ctx->file_data)->cpusubtype;
        } else {
            if (MACHO_REQUIRES_SWAP(*(uint32_t *)ctx->file_data)) swap_mach_header_64((struct mach_header_64 *)ctx->file_data, 0);
            file_type = ((struct mach_header_64 *)ctx->file_data)->filetype;
            cpu_type = ((struct mach_header_64 *)ctx->file_data)->cputype;
            cpu_subtype = ((struct mach_header_64 *)ctx->file_data)->cpusubtype;
        }
        
        if (macho_supported(cpu_type, cpu_subtype, file_type)) {
            ctx->slice_list[ctx->slice_count].cpu_type = cpu_type;
            ctx->slice_list[ctx->slice_count].cpu_subtype = cpu_subtype;
            ctx->slice_list[ctx->slice_count].offset = 0;
            ctx->slice_list[ctx->slice_count].size = ctx->file_size;
            ctx->slice_list[ctx->slice_count].file_data = ctx->file_data;
            ctx->slice_list[ctx->slice_count].file_size = ctx->file_size;
            
            ctx->slice_list[ctx->slice_count].hdr = ctx->file_data;
            ctx->slice_list[ctx->slice_count].is_32bit = MACHO_32BIT(ctx->slice_list[ctx->slice_count].hdr32->magic);
            ctx->slice_list[ctx->slice_count].has_ptrauth = ((cpu_type == CPU_TYPE_ARM64) && (cpu_subtype & CPU_SUBTYPE_ARM64E) != 0);
            
            if (ctx->slice_list[ctx->slice_count].is_32bit) {
                ctx->slice_list[ctx->slice_count].load_cmd = (struct load_command *)(ctx->slice_list[ctx->slice_count].hdr32 + 1);
                ctx->slice_list[ctx->slice_count].cmd_count = ctx->slice_list[ctx->slice_count].hdr32->ncmds;
            } else {
                ctx->slice_list[ctx->slice_count].load_cmd = (struct load_command *)(ctx->slice_list[ctx->slice_count].hdr64 + 1);
                ctx->slice_list[ctx->slice_count].cmd_count = ctx->slice_list[ctx->slice_count].hdr64->ncmds;
            }
            ctx->slice_count++;
        }
    }
    
    if (ctx->slice_count == 0) goto err;
    ctx->path = strdup(path);
    return ctx;

err:
    if (fd >= 0) close(fd);
    macho_release(ctx);
    return NULL;
}

void macho_release_rpaths(macho_rpaths_t *rpaths) {
    if (rpaths == NULL) return;
    if (rpaths->list != NULL) {
        for (uint32_t i = 0; i < rpaths->count; i++) {
            if (rpaths->list[i] != NULL && rpaths->list[i] != rpaths->relative_path) {
                free(rpaths->list[i]);
            }
        }
        free(rpaths->list);
    }

    if (rpaths->relative_path != NULL) free(rpaths->relative_path);
    free(rpaths);
}

macho_rpaths_t *macho_resolve_rpaths(macho_ctx_t *ctx) {
    if (ctx == NULL || ctx->path == NULL) return NULL;
    macho_rpaths_t *rpaths = calloc(1, sizeof(macho_rpaths_t));
    if (rpaths == NULL) goto err;

    size_t path_len = strlen(ctx->path);
    rpaths->relative_path = strdup(ctx->path);
    int idx = (int)path_len;
    for (; rpaths->relative_path[idx] != '/' && idx > 0; idx--);
    
    if (idx == 0) goto err;
    rpaths->relative_path[idx] = '\0';

    macho_slice_t *slice = macho_get_best_slice(ctx);
    if (slice == NULL) goto err;
    
    struct load_command *load_cmd = slice->load_cmd;
    for (uint32_t i = 0; i < slice->cmd_count; i++){
        if (load_cmd->cmd == LC_RPATH) rpaths->count++;
        load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
    }
    
    uint32_t add_count = 0;
    rpaths->list = calloc(1, (rpaths->count+6) * sizeof(char *));
    if (rpaths->list == NULL) goto err;

    load_cmd = slice->load_cmd;
    for (uint32_t i = 0; i < slice->cmd_count; i++){
        if (load_cmd->cmd == LC_RPATH) {
            struct rpath_command *rpath_cmd = (struct rpath_command *)load_cmd;
            const char *current_rpath = (char *)rpath_cmd + rpath_cmd->path.offset;
            char *replace_prefix = NULL;
            uint32_t start_count = add_count;
            
            if (strncmp(current_rpath, "@loader_path", 12) == 0 && (current_rpath[12] == '/' || current_rpath[12] == '\0')) {
                replace_prefix = "@loader_path";
            } else if (strncmp(current_rpath, "@executable_path", 16) == 0 && (current_rpath[16] == '/' || current_rpath[16] == '\0')) {
                replace_prefix = "@executable_path";
            } else if (current_rpath[0] == '.' && current_rpath[1] == '/') {
                replace_prefix = ".";
            } else if (strncmp(current_rpath, "/var/jb", 7) == 0) {
                rpaths->list[add_count++] = strdup(current_rpath + 7);
            } else if (current_rpath[0] != '.' && current_rpath[0] != '/' && current_rpath[0] != '@') { // ????
                uint32_t path_size = (uint32_t)(strlen(rpaths->relative_path) + strlen(current_rpath) + 2);
                char *new_path = calloc(1, path_size);
                if (new_path != NULL) {
                    snprintf(new_path, path_size-1, "%s/%s", rpaths->relative_path, current_rpath);
                    rpaths->list[add_count++] = strdup(new_path);
                }
            } else {
                rpaths->list[add_count++] = strdup(current_rpath);
            }

            if (replace_prefix != NULL) {
                size_t base_len = strnlen(current_rpath, PATH_MAX);
                size_t replace_len = strnlen(replace_prefix, PATH_MAX);
                size_t relative_len = strnlen(rpaths->relative_path, PATH_MAX);

                if ((base_len + relative_len - replace_len + 1) > PATH_MAX) return NULL;
                char path_buf[PATH_MAX] = {0};

                char *entry = strnstr(current_rpath, replace_prefix, base_len);
                intptr_t entry_offset = (intptr_t)((uintptr_t)entry - (uintptr_t)current_rpath);
                if (entry_offset > 0) memcpy(path_buf, current_rpath, entry_offset);

                memcpy(path_buf+strlen(path_buf), rpaths->relative_path, relative_len);
                memcpy(path_buf+strlen(path_buf), entry+replace_len, base_len-replace_len);
                rpaths->list[add_count++] = strdup(path_buf);
            }

            if (start_count < add_count && rpaths->list[start_count] != NULL) {
                if (rpaths->list[start_count] != NULL) {
                    if (use_stock_libswift()) {
                        if (strcmp(rpaths->list[start_count], "/usr/lib/libswift/stable") == 0) {
                            free(rpaths->list[start_count]);
                            rpaths->list[start_count] = strdup("/usr/lib/swift");
                        }
                    } else {
                        if (strcmp(rpaths->list[start_count], "/usr/lib/swift") == 0) {
                            if (access(rpaths->list[start_count], F_OK) == 0) {
                                rpaths->list[add_count++] = rpaths->list[start_count];
                                rpaths->list[start_count] = strdup("/usr/lib/libswift/stable");
                            } else {
                                free(rpaths->list[start_count]);
                                rpaths->list[start_count] = strdup("/usr/lib/libswift/stable");
                            }
                        }
                    }
                }
            }
        }
        load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
    }

    char path_buf[PATH_MAX] = {0};
    snprintf(path_buf, PATH_MAX-1, "%s/lib", rpaths->relative_path);
    if (access(path_buf, F_OK) == 0) rpaths->list[add_count++] = strdup(path_buf);

    bzero(path_buf, PATH_MAX);
    snprintf(path_buf, PATH_MAX-1, "%s/Frameworks", rpaths->relative_path);
    if (access(path_buf, F_OK) == 0) rpaths->list[add_count++] = strdup(path_buf);

    rpaths->list[add_count++] = rpaths->relative_path;
    rpaths->list[add_count] = NULL;
    rpaths->count = add_count;
    return rpaths;

err:
    macho_release_rpaths(rpaths);
    return NULL;
}

static int macho_append_dep(macho_deps_t *deps, char *path) {
    if (path == NULL) return -1;
    if (deps == NULL || deps->count == deps->max || access(path, F_OK) != 0) goto remove;

    bool should_add = true;
    for (int i = 0; i < deps->count; i++) {
        if (deps->list[i] != NULL && strcmp(path, deps->list[i]) == 0) {
            should_add = false;
            break;
        }
    }

    if (use_stock_libswift()) {
        if (strstr(path, "/usr/lib/libswift/stable") != NULL) should_add = false;
    }

    if (should_add == false) goto remove;
    deps->list[deps->count++] = path;
    return 0;

remove:
    free(path);
    return -1;
}

static char *macho_replace_path(char *path, char *target, char *replacment) {
    if (path == NULL || target == NULL || replacment == NULL) return NULL;
    if ((((uint64_t)path) & 0xfffffffff) != (uint64_t)path) return NULL;
    if ((((uint64_t)target) & 0xfffffffff) != (uint64_t)target) return NULL;
    if ((((uint64_t)replacment) & 0xfffffffff) != (uint64_t)replacment) return NULL;

    size_t path_len = strnlen(path, PATH_MAX);
    size_t target_len = strnlen(target, PATH_MAX);
    size_t replacment_len = strnlen(replacment, PATH_MAX);
    
    if (path_len + replacment_len - target_len + 1 > PATH_MAX) return NULL;
    char path_buf[PATH_MAX] = {0};
    
    char *entry = strnstr(path, target, path_len);
    intptr_t entry_offset = (intptr_t)((uintptr_t)entry - (uintptr_t)path);
    if (entry_offset > 0) memcpy(path_buf, path, entry_offset);
    
    memcpy(path_buf+strlen(path_buf), replacment, replacment_len);
    memcpy(path_buf+strlen(path_buf), entry+target_len, path_len-target_len);
    if (access(path_buf, F_OK) != 0) return NULL;

    char final_path[PATH_MAX] = {0};
    char *resolved = realpath(path_buf, final_path);
    if (resolved != NULL) return strdup(resolved);
    return NULL;
}

static int macho_resolve_sub_deps(macho_deps_t *deps) {
    if (deps == NULL) return -1;
    if (deps->count == deps->max) return 0;
    
    uint32_t start_count = deps->count;
    for (uint32_t i = deps->resolved; i < start_count; i++) {
        macho_ctx_t *ctx = macho_load(deps->list[i]);
        if (ctx == NULL) {
            deps->resolved++;
            continue;
        }

        macho_rpaths_t *rpaths = macho_resolve_rpaths(ctx);
        if (rpaths == NULL) {
            macho_release(ctx);
            deps->resolved++;
            continue;
        }

        macho_slice_t *slice = macho_get_best_slice(ctx);
        if (slice == NULL) {
            macho_release(ctx);
            deps->resolved++;
            continue;
        }
        
        struct load_command *load_cmd = slice->load_cmd;
        for (uint32_t j = 0; j < slice->cmd_count; j++){
            if (DYLIB_LOADCMD(load_cmd->cmd)) {
                struct dylib_command *dylib_cmd = (struct dylib_command *)load_cmd;
                char *current_dep = (char *)dylib_cmd + dylib_cmd->dylib.name.offset;
    
                if (current_dep[0] == '@') {
                    if (strncmp(current_dep, "@loader_path", 12) == 0 && (current_dep[12] == '/' || current_dep[12] == '\0')) {
                        macho_append_dep(deps, macho_replace_path(current_dep, "@loader_path", rpaths->relative_path));
                    } else if (strncmp(current_dep, "@executable_path", 16) == 0 && (current_dep[16] == '/' || current_dep[16] == '\0')) {
                        macho_append_dep(deps, macho_replace_path(current_dep, "@executable_path", rpaths->relative_path));
                    } else if (strncmp(current_dep, "@rpath", 6) == 0 && (current_dep[6] == '/' || current_dep[6] == '\0')) {
                        bool found_rpath = false;
                        if (rpaths != NULL) {
                            for (uint32_t j = 0; j < rpaths->count; j++) {
                                char *dep_path = macho_replace_path(current_dep, "@rpath", rpaths->list[j]);
                                if (dep_path != NULL) {
                                    macho_append_dep(deps, dep_path);
                                    found_rpath = true;
                                    break;
                                }
                            }
                        }

                        if (!found_rpath) {
                            for (uint32_t j = 0; default_lib_paths[j] != NULL; j++) {
                                char *dep_path = macho_replace_path(current_dep, "@rpath", default_lib_paths[j]);
                                if (dep_path != NULL) {
                                    macho_append_dep(deps, dep_path);
                                    found_rpath = true;
                                    break;
                                }
                            }

                            if (!found_rpath) {
                                if (!use_stock_libswift() && access("/usr/lib/libswift/stable", F_OK) == 0) {
                                    char *dep_path = macho_replace_path(current_dep, "@rpath", default_lib_paths[j]);
                                    if (dep_path != NULL) {
                                        macho_append_dep(deps, dep_path);
                                        found_rpath = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    if (access(current_dep, F_OK) == 0) {
                        char full_path[PATH_MAX] = {0};
                        char *resolved = realpath(current_dep, full_path);
                        if (resolved != NULL) {
                            macho_append_dep(deps, strdup(resolved));
                        }
                    }
                }
            }
            load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
        }

        macho_release(ctx);
        macho_release_rpaths(rpaths);
        deps->resolved++;
    }

    if (deps->count > start_count) macho_resolve_sub_deps(deps);
    return 0;
}

void macho_release_deps(macho_deps_t *deps) {
    if (deps == NULL) return;
    if (deps->list != NULL) {
        for (uint32_t i = 0; i < deps->count; i++) {
            if (deps->list[i] != NULL) free(deps->list[i]);
        }
        free(deps->list);
    }
    free(deps);
}

bool macho_uses_external_libswift(macho_deps_t *deps) {
    if (deps == NULL || use_stock_libswift()) return false;
    if (deps->list != NULL) {
        for (uint32_t i = 0; i < deps->count; i++) {
            if (deps->list[i] != NULL) {
                if (strstr(deps->list[i], "/usr/lib/libswift/stable") != NULL) {
                    return true;
                }
            }
        }
    }
    return false;
}

macho_deps_t *macho_resolve_deps(macho_ctx_t *ctx, macho_rpaths_t *rpaths) {
    if (ctx == NULL) return NULL;
    macho_deps_t *deps = calloc(1, sizeof(macho_deps_t));
    if (deps == NULL) goto err;

    deps->max = 128;
    deps->list = calloc(1, (deps->max + 1) * sizeof(char *));
    if (deps->list == NULL) goto err;

    deps->list[deps->count++] = strdup(ctx->path);
    macho_resolve_sub_deps(deps);
    return deps;

err:
    macho_release_deps(deps);
    return NULL;
}

macho_signature_t *macho_get_signature(macho_slice_t *slice) {
    if (slice == NULL) return NULL;
    struct load_command *load_cmd = slice->load_cmd;
    struct linkedit_data_command *linkedit = NULL;

    for (uint32_t i = 0; i < slice->cmd_count; i++){
        if (load_cmd->cmd == LC_CODE_SIGNATURE) {
            linkedit = (struct linkedit_data_command *)load_cmd;
            break;
        }
        load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
    }

    if (linkedit == NULL) return NULL;
    CS_SuperBlob *blob = (CS_SuperBlob *)((uint8_t *)slice->hdr + linkedit->dataoff);
    CS_CodeDirectory *best_cd = NULL;
    uint8_t hash_data[128] = {0};
    uint32_t best_rank = 0;
    bool is_adhoc = true;
    
    for (uint32_t i = 0; i < ntohl(blob->count); i++) {
        const CS_BlobIndex *index = &blob->index[i];
        uint32_t type = ntohl(index->type);
        uint32_t offset = ntohl(index->offset);
        if (ntohl(blob->length) < offset) break;
        
        if (type == CSSLOT_CODEDIRECTORY || (type >= CSSLOT_ALTERNATE_CODEDIRECTORIES && type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
            CS_CodeDirectory *cd = (CS_CodeDirectory *)((uint8_t *)blob + offset);
            uint32_t rank = 0;
            switch (cd->hashType) {
                case CS_HASHTYPE_SHA256_TRUNCATED: rank = 2; break;
                case CS_HASHTYPE_SHA256: rank = 3; break;
                case CS_HASHTYPE_SHA384: rank = 4; break;
                case CS_HASHTYPE_SHA1: rank = 1; break;
                default: break;
            }
        
            if (rank > best_rank) {
                best_cd = cd;
                bzero(hash_data, sizeof(hash_data));
                uint32_t size = ntohl(cd->length);
                best_rank = rank;

                switch (cd->hashType) {
                    case CS_HASHTYPE_SHA1: CC_SHA1(cd, size, hash_data); break;
                    case CS_HASHTYPE_SHA256:
                    case CS_HASHTYPE_SHA256_TRUNCATED: CC_SHA256(cd, size, hash_data); break;
                    case CS_HASHTYPE_SHA384: CC_SHA384(cd, size, hash_data); break;
                    default: break;
                }
            }
        } else if (type == CSSLOT_SIGNATURESLOT) {
            CS_GenericBlob *signature = (CS_GenericBlob *)((uint8_t *)blob + offset);
            if (ntohl(signature->length) > sizeof(CS_GenericBlob)) is_adhoc = false;
        }
    }

    if (best_rank == 0 || best_cd == NULL) return NULL;
    macho_signature_t *signature = calloc(1, sizeof(macho_signature_t));
    if (signature == NULL) return NULL;
    
    signature->is_adhoc = is_adhoc;
    if (!signature->is_adhoc) {
        if ((ntohl(best_cd->flags) & 0x0002) == 0x0002) {
            signature->is_adhoc = true;
        }
    }
    
    memcpy(signature->hash, hash_data, 20);
    signature->hash_type = best_cd->hashType;
    signature->offset = linkedit->dataoff;
    signature->size = linkedit->datasize;
    signature->code_dir = best_cd;
    signature->version = ntohl(best_cd->version);
    return signature;
}

void macho_release_signature(macho_signature_t *signature) {
    if (signature == NULL) return;
    free(signature);
}

macho_slice_t *macho_get_best_slice(macho_ctx_t *ctx) {
    if (ctx == NULL || ctx->slice_list == NULL || ctx->slice_count == 0) return NULL;
    if (ctx->slice_count == 1) return &ctx->slice_list[0];
    
    uint32_t arm64_idx = -1;
    for (uint32_t i = 0; i < ctx->slice_count; i++) {
        if (ctx->slice_list[i].cpu_type == CPU_TYPE_ARM64) {
            if (ctx->slice_list[i].cpu_subtype == CPU_SUBTYPE_ARM64_V8 || ctx->slice_list[i].cpu_subtype == CPU_SUBTYPE_ARM64_ALL) {
                if (!soc_is_arm64e()) return &ctx->slice_list[i];
                arm64_idx = i;
            } else if (soc_is_arm64e() && ctx->slice_list[i].has_ptrauth) {
                return &ctx->slice_list[i];
            }
        }
    }
    
    if (arm64_idx != -1) return &ctx->slice_list[arm64_idx];
    return &ctx->slice_list[0];
}

static int super_blob_add(macho_super_blob_t *super_blob, uint32_t type, uint8_t *data, uint32_t size) {
    if (super_blob == NULL || data == NULL || size == 0 || (super_blob->entry_count+1) >= 8) return -1;
    super_blob->entries[super_blob->entry_count].type = type;
    super_blob->entries[super_blob->entry_count].size = size;
    super_blob->entries[super_blob->entry_count].data = data;
    super_blob->entries[super_blob->entry_count++].offset = 0;
    return 0;
}

static int super_blob_build(macho_super_blob_t *super_blob, uint8_t **out_data, uint32_t *out_size) {
    if (super_blob == NULL || out_data == NULL || out_size == 0 || super_blob->entry_count == 0) return -1;
    uint32_t full_size = sizeof(CS_SuperBlob) + (sizeof(CS_BlobIndex) * super_blob->entry_count);
    
    for (uint32_t i = 0; i < super_blob->entry_count; i++) {
        super_blob->entries[i].offset = full_size;
        full_size += super_blob->entries[i].size;
    }

    uint8_t *data = calloc(1, full_size);
    if (data == NULL) return -1;

    CS_SuperBlob *blob = (CS_SuperBlob *)data;
    blob->magic = htonl(CSMAGIC_EMBEDDED_SIGNATURE);
    blob->length = htonl(full_size);
    blob->count = htonl(super_blob->entry_count);


    CS_BlobIndex *index = (CS_BlobIndex *)(data + sizeof(CS_SuperBlob));
    for (uint32_t i = 0; i < super_blob->entry_count; i++) {
        index[i].offset = htonl(super_blob->entries[i].offset);
        index[i].type = htonl(super_blob->entries[i].type);
        memcpy(data + super_blob->entries[i].offset, super_blob->entries[i].data, super_blob->entries[i].size);
    }

    *out_data = data;
    *out_size = full_size;
    return 0;
}

int macho_sign_binary(macho_slice_t *slice, char *ident, uint8_t **out_data, uint32_t *out_size, uint8_t *cd_hash) {
    macho_super_blob_t *super_blob = NULL;
    macho_signature_t *signature = NULL;
    uint8_t *cd_data = NULL;
    int status = -1;

    if ((super_blob = calloc(1, sizeof(macho_super_blob_t))) == NULL) goto done;
    uint32_t code_limit = slice->size;
    signature = macho_get_signature(slice);
    if (signature != NULL) code_limit = ntohl(signature->code_dir->codeLimit);
    
    uint32_t hash_slots = ((code_limit + 0xfff) & ~0xfff) / 0x1000;
    uint32_t cd_size = sizeof(CS_CodeDirectory) + 32 + (hash_slots * 32);
    if ((cd_data = calloc(1, cd_size)) == NULL) goto done;
    CS_CodeDirectory *code_dir = (CS_CodeDirectory *)cd_data;

    code_dir->magic = htonl(CSMAGIC_CODEDIRECTORY);
    code_dir->length = htonl(cd_size);
    code_dir->version = htonl(0x20400);
    code_dir->identOffset = htonl(sizeof(CS_CodeDirectory));
    code_dir->hashOffset = htonl(sizeof(CS_CodeDirectory) + 32);
    code_dir->codeLimit = htonl(code_limit);
    code_dir->nCodeSlots = htonl(hash_slots);
    code_dir->hashSize = 32;
    code_dir->hashType = CS_HASHTYPE_SHA256;
    code_dir->pageSize = 0xc;

    uint32_t ident_size = (uint32_t)strnlen(ident, 31);
    memcpy(cd_data + sizeof(CS_CodeDirectory), ident, ident_size);

    for (uint32_t i = 0; i < hash_slots; i++) {
        uint8_t *hash_slot = cd_data + ntohl(code_dir->hashOffset) + (i * 32);
        uint64_t page_offset = (uint64_t)(i * 0x1000);

        uint8_t *code_data = slice->file_data + slice->offset + page_offset;
        uint32_t code_size = 0x1000;
        if (i == (hash_slots - 1)) code_size = code_limit - (uint32_t)page_offset;
        CC_SHA256(code_data, code_size, hash_slot);
    }

    CC_SHA256(code_dir, cd_size, cd_hash);
    super_blob_add(super_blob, CSSLOT_CODEDIRECTORY, cd_data, cd_size);
    if (signature != NULL) {
        CS_SuperBlob *attached_super_blob = (CS_SuperBlob *)(slice->file_data + slice->offset + signature->offset);
        if (ntohl(attached_super_blob->magic) == CSMAGIC_EMBEDDED_SIGNATURE) {
            uint32_t count = ntohl(attached_super_blob->count);

            for (int i = 0; i < count; i++) {
                CS_BlobIndex *index = &attached_super_blob->index[i];
                uint32_t type = ntohl(index->type);
                uint32_t offset = ntohl(index->offset);

                CS_GenericBlob *sub_blob = (CS_GenericBlob *)((uint64_t)attached_super_blob + offset);
                uint32_t sub_length = ntohl(attached_super_blob->length) - offset;
                if (sub_length < sizeof(CS_GenericBlob) || sub_length < ntohl(sub_blob->length)) break;
                sub_length = ntohl(sub_blob->length);

                if (type == CSSLOT_ENTITLEMENTS || type == CSSLOT_DER_ENTITLEMENTS || type == CSSLOT_REQUIREMENTS) {
                    super_blob_add(super_blob, type, (uint8_t *)sub_blob, sub_length);
                }
            }
        }
    }
    status = super_blob_build(super_blob, out_data, out_size);

done:
    if (super_blob != NULL) free(super_blob);
    if (signature != NULL) macho_release_signature(signature);
    if (cd_data != NULL) free(cd_data);
    return status;
}

bool macho_should_process(macho_ctx_t *ctx) {
    if (ctx == NULL || ctx->slice_count == 0) return false;
    if (ctx->path != NULL && strstr(ctx->path, "/var/containers") != NULL) {
        macho_slice_t *slice = macho_get_best_slice(ctx);
        if (slice == NULL) return false;

        macho_signature_t *signature = macho_get_signature(slice);
        if (signature == NULL) return false;
        
        bool adhoc = signature->is_adhoc;
        macho_release_signature(signature);
        if (!adhoc) return false;
    }
    return true;
}