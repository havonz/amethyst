#include "basebin_dyld.h"

dyld_info_t *dyld_info = NULL;

static dyld_cache_ranged_mapping_t *dyld_cache_map_range(int fd, uint32_t offset, uint32_t size) {
    dyld_cache_ranged_mapping_t *mapping = calloc(1, sizeof(dyld_cache_ranged_mapping_t));
    if (mapping == NULL) return NULL;

    uint32_t map_offset = (uint32_t)(trunc_page(offset));
    mapping->aligned_size = (uint32_t)(round_page(size));
    mapping->size = size;

    lseek(fd, 0, SEEK_SET);
    mapping->aligned_data = mmap(NULL, mapping->aligned_size, PROT_READ, MAP_PRIVATE, fd, map_offset);
    if (mapping->aligned_data == MAP_FAILED) {
        free(mapping);
        return NULL;
    }

    mapping->data = (void *)((uintptr_t)mapping->aligned_data + (offset - map_offset));
    return mapping;
}

static void dyld_cache_unmap_range(dyld_cache_ranged_mapping_t *mapping) {
    if (mapping == NULL) return;
    if (mapping->aligned_data != NULL) {
        munmap(mapping->aligned_data, mapping->aligned_size);
    }
    free(mapping);
}

static int32_t dyld_cache_image_index(const char *path) {
    if (dyld_info == NULL || path == NULL) return -1;
    uint32_t image_count = 0;
    uint32_t images_offset = 0;

    if (dyld_info->cache_hdr->mappingOffset >= offsetof(dyld_cache_header_t, imagesOffset)) {
        images_offset = dyld_info->cache_hdr->imagesOffset;
        image_count = dyld_info->cache_hdr->imagesCount;
    } else {
        images_offset = dyld_info->cache_hdr->imagesOffsetLegacy;
        image_count = dyld_info->cache_hdr->imagesCountLegacy;
    }

    if (images_offset == 0 || image_count == 0) return -1;
    dyld_cache_image_info_t *image_list = (dyld_cache_image_info_t *)((uint8_t *)dyld_info->cache_hdr + images_offset);

    for (int32_t idx = 0; idx < image_count; idx++) {
        char *image_path = ((char *)dyld_info->cache_hdr) + image_list[idx].pathFileOffset;
        if (strcmp(image_path, path) == 0) {
            return idx;
        }
    }
    return -1;
}

void *dyld_cache_find_symbol(const char *path, const char *name) {
    uint32_t image_idx = dyld_cache_image_index(path);
    if (image_idx == -1) return NULL;

    nlist_t *symbol_table = (nlist_t *)dyld_info->symbol_mapping->data;
    char *string_table = (char *)dyld_info->string_mapping->data;
    uint32_t start_idx = 0;
    uint32_t end_idx = 0;

    if (dyld_info->legacy_entries) {
        dyld_cache_local_symbols_entry_t *symbols_entry = (dyld_cache_local_symbols_entry_t *)dyld_info->entry_mapping->data;
        start_idx = symbols_entry[image_idx].nlistStartIndex;
        end_idx = start_idx + symbols_entry[image_idx].nlistCount;
    } else {
        dyld_cache_local_symbols_entry_64_t *symbols_entry = (dyld_cache_local_symbols_entry_64_t *)dyld_info->entry_mapping->data;
        start_idx = symbols_entry[image_idx].nlistStartIndex;
        end_idx = start_idx + symbols_entry[image_idx].nlistCount;
    }

    if (end_idx > dyld_info->symbol_info.nlistCount) return NULL;
    for (uint32_t i = start_idx; i < end_idx; i++) {
        if (strcmp(name, string_table + symbol_table[i].n_un.n_strx) == 0) {
            return (void *)(symbol_table[i].n_value + dyld_info->cache_slide);
        }
    }
    return NULL;
}

void *dyld_find_symbol(const char *name) {
    if (dyld_info == NULL || dyld_info->dyld_base == 0) return NULL;
    mach_header_t *hdr = (mach_header_t *)dyld_info->dyld_base;
    struct load_command *load_cmd = (struct load_command *)(hdr + 1);
    struct symtab_command *symbol_table = NULL;
    uintptr_t string_offset = 0;
    uintptr_t symbol_offset = 0;

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (load_cmd->cmd == LC_SYMTAB) {
            symbol_table = (struct symtab_command *)load_cmd;
            break;
        }
        load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
    }

    load_cmd = (struct load_command *)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            segment_command_t *segment = (segment_command_t *)load_cmd;

            if (strcmp(segment->segname, "__LINKEDIT") == 0) {
                if ((symbol_table->symoff - segment->fileoff) < segment->filesize) {
                    symbol_offset = (uintptr_t)(segment->vmaddr + symbol_table->symoff - segment->fileoff);
                }
                
                if ((symbol_table->stroff - segment->fileoff) < segment->filesize) {
                    string_offset = (uintptr_t)(segment->vmaddr + symbol_table->stroff - segment->fileoff);
                }
            }
            if (symbol_offset != 0 && symbol_offset != 0) break;
        }
        load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
    }

    nlist_t *symbol = (nlist_t *)(dyld_info->dyld_base + symbol_offset);
    for (uint32_t i = 0; i < symbol_table->nsyms; i++) {
        uint64_t idx = symbol[i].n_un.n_strx;
        if (idx >= symbol_table->strsize || idx == 0) continue;
        if ((symbol[i].n_type & N_SECT) == 0 || symbol[i].n_sect == NO_SECT) continue;

        if (strcmp((const char *)(dyld_info->dyld_base + string_offset + idx), name) == 0) {
            if (symbol[i].n_value == 0) continue;
            return (void *)(dyld_info->dyld_base + symbol[i].n_value);
        }
    }
    return NULL;
}

void dyld_deinit(void) {
    if (dyld_info == NULL) return;
    if (dyld_info->entry_mapping != NULL) dyld_cache_unmap_range(dyld_info->entry_mapping);
    if (dyld_info->symbol_mapping != NULL) dyld_cache_unmap_range(dyld_info->symbol_mapping);
    if (dyld_info->string_mapping != NULL) dyld_cache_unmap_range(dyld_info->string_mapping);
    
    free(dyld_info);
    dyld_info = NULL;
}

int dyld_init(void) {
    task_dyld_info_data_t info = {0};
    uint32_t count = TASK_DYLD_INFO_COUNT;
    int fd = -1;

    if ((dyld_info = calloc(1, sizeof(dyld_info_t))) == NULL) goto err;
    task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &count);
    dyld_all_image_infos_t *all_image_infos = (dyld_all_image_infos_t *)info.all_image_info_addr;
    if (all_image_infos == NULL) goto err;

    dyld_info->cache_hdr = (dyld_cache_header_t *)all_image_infos->sharedCacheBaseAddress;
    dyld_info->cache_slide = (uintptr_t)all_image_infos->sharedCacheSlide;
    dyld_info->dyld_base = (uintptr_t)all_image_infos->dyldImageLoadAddress;

    if ((fd = open(dyld_shared_cache_file_path(), O_RDONLY)) < 0) goto err;
    dyld_cache_header_t hdr = {};

    read(fd, &hdr, sizeof(dyld_cache_header_t));
    if (hdr.localSymbolsOffset == 0 || hdr.localSymbolsSize == 0) goto err;

    dyld_info->legacy_entries = !(hdr.mappingOffset >= offsetof(dyld_cache_header_t, symbolFileUUID));
    lseek(fd, hdr.localSymbolsOffset, SEEK_SET);
    read(fd, &dyld_info->symbol_info, sizeof(dyld_cache_local_symbols_info_t));
    
    uint32_t entries_offset = (uint32_t)(hdr.localSymbolsOffset + dyld_info->symbol_info.entriesOffset);
    uint32_t entries_size = 0;
    if (dyld_info->legacy_entries) {
        entries_size = (dyld_info->symbol_info.entriesCount * sizeof(dyld_cache_local_symbols_entry_t));
    } else {
        entries_size = (dyld_info->symbol_info.entriesCount * sizeof(dyld_cache_local_symbols_entry_64_t));
    }

    if ((dyld_info->entry_mapping = dyld_cache_map_range(fd, entries_offset, entries_size)) == NULL) goto err;
    uint32_t symbol_offset = (uint32_t)(hdr.localSymbolsOffset + dyld_info->symbol_info.nlistOffset);
    uint32_t symbol_size = dyld_info->symbol_info.nlistCount * sizeof(nlist_t);

    if ((dyld_info->symbol_mapping = dyld_cache_map_range(fd, symbol_offset, symbol_size)) == NULL) goto err;
    uint32_t string_offset = (uint32_t)(hdr.localSymbolsOffset + dyld_info->symbol_info.stringsOffset);
    uint32_t string_size = dyld_info->symbol_info.stringsSize;

    if ((dyld_info->string_mapping = dyld_cache_map_range(fd, string_offset, string_size)) == NULL) goto err;
    close(fd);
    return 0;

err:
    if (fd >= 0) close(fd);
    dyld_deinit();
    return -1;
}
