#include "util.h"
#include "memory.h"
#include "dma.h"
#include "trustcache.h"
#include "codesign.h"

static int create_cs_blob(int fd, char *path, uint32_t slice_offset, uint64_t vnode, uint64_t ubc_info) {
    macho_ctx_t *macho = macho_load(path);
    if (macho == NULL) return -1;

    macho_slice_t *slice = NULL;
    for (uint32_t i = 0; i < macho->slice_count; i++) {
        if (macho->slice_list[i].offset == slice_offset) {
            slice = &macho->slice_list[i];
            break;
        }
    }

    if (slice == NULL) {
        macho_release(macho);
        return -1;
    }

    uint8_t *cs_data = NULL;
    uint32_t cs_size = 0;
    uint8_t cd_hash[32] = {0};
    char *ident = (char *)resolve_binary_name(path);
    if (ident == NULL) ident = "amethyst-codesign";

    int status = macho_sign_binary(slice, ident, &cs_data, &cs_size, cd_hash);
    macho_release(macho);
    if (status != 0) return -1;

    uint64_t cs_blob = kread64(ubc_info + koffsetof(ubc_info, cs_blob));
    if (cs_blob != 0) {
        while (cs_blob != 0) {
            uint32_t current_hash[20] = {0};
            kread_buf(cs_blob + offsetof(cs_blob_t, csb_cdhash), current_hash, 20);
            if (memcmp(cd_hash, current_hash, 20) == 0) {
                free(cs_data);
                return 0;
            }
            cs_blob = kread64(cs_blob);
        }
    }
    
    if (!trustcache_check(cd_hash)) {
        trustcache_lock_add_hash(cd_hash, CS_HASHTYPE_SHA256);
    }
    
    lseek(fd, 0, SEEK_SET);
    fsignatures_t signature = {0};
    signature.fs_file_start = slice->offset;
    signature.fs_blob_start = (void *)cs_data;
    signature.fs_blob_size = cs_size;

    status = fcntl(fd, F_ADDSIGS, &signature);
    free(cs_data);
    if (status != 0) return -1;
    
    ubc_info = kread64(vnode + koffsetof(vnode, ubcinfo));
    if (ubc_info == 0) return -1;

    cs_blob = kread64(ubc_info + koffsetof(ubc_info, cs_blob));
    if (cs_blob == 0) return -1;

    cs_blob_t blob_data = {0};
    kread_buf(cs_blob, &blob_data, sizeof(cs_blob_t));

    blob_data.csb_flags &= ~(CS_HARD|CS_RESTRICT|CS_KILL|CS_REQUIRE_LV);
    blob_data.csb_flags |= CS_VALID|CS_SIGNED|CS_GET_TASK_ALLOW|CS_DEBUGGED|CS_PLATFORM_PATH|CS_PLATFORM_BINARY;
    blob_data.csb_platform.binary = 1;
    blob_data.csb_signer_type = CS_SIGNER_TYPE_UNKNOWN;
    blob_data.csb_reconstituted = 1;
    blob_data.csb_base_offset = slice->offset;
    blob_data.csb_mem_size = cs_size;
    blob_data.csb_cpu_type = CPU_TYPE_ARM64;
    
    kwrite_buf(cs_blob, &blob_data, sizeof(cs_blob_t));

#ifdef __arm64e__
    uint64_t pmap_cs = kread64(cs_blob + 0xb0);
    if (pmap_cs != 0 && pmap_cs != 0xdeadbeefdeadbeef) {
        uint32_t current_trustlevel = kread32(pmap_cs + koffsetof(pmap_cs_code_directory, trust));
        if (current_trustlevel != 1) {
            uint64_t trustlevel_pa = kvtophys(pmap_cs + koffsetof(pmap_cs_code_directory, trust));
            if (trustlevel_pa != 0) dma_write32(trustlevel_pa, 1);
        }
    }
#endif
    return 0;
}

int sign_binary(char *path, uint32_t le_offset, uint32_t le_size, uint32_t slice_offset, uint32_t file_type) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    uint64_t vnode = vnode_for_fd(fd);
    if (vnode == 0) goto err;

    uint64_t ubc_info = kread64(vnode + koffsetof(vnode, ubcinfo));
    if (ubc_info == 0) goto err;

#ifndef __arm64e__
    uint64_t cs_blob = kread64(ubc_info + koffsetof(ubc_info, cs_blob));
    if (cs_blob != 0) return 0;
#endif

    if (create_cs_blob(fd, path, slice_offset, vnode, ubc_info) != 0) goto err;
    if (kread64(vnode + koffsetof(ubc_info, cs_blob)) == 0) goto err;
    close(fd);
    return 0;

err:
    if (fd >= 0) close(fd);
    return -1;
}

int fixup_cs_flags(uint64_t proc) {
    if (proc == 0) return -1;
    uint32_t add_flags = CS_PLATFORM_BINARY | CS_VALID | CS_DEBUGGED | CS_INVALID_ALLOWED | CS_GET_TASK_ALLOW;
    uint32_t remove_flags = CS_RESTRICT | CS_HARD | CS_KILL | CS_REQUIRE_LV | CS_FORCED_LV | CS_ENFORCEMENT;

    uint32_t cs_flags = kread32(proc + koffsetof(proc, csflags));
    cs_flags &= ~remove_flags;
    cs_flags |= add_flags;

    kwrite32(proc + koffsetof(proc, csflags), cs_flags);
    return 0;
}
