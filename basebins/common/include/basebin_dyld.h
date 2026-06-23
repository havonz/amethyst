#ifndef basebin_dyld_h
#define basebin_dyld_h

#include "basebin_common.h"

typedef struct {
    char magic[16];
    uint32_t mappingOffset;
    uint32_t mappingCount;
    uint32_t imagesOffsetLegacy;
    uint32_t imagesCountLegacy;
    uint64_t dyldBaseAddress;
    uint64_t codeSignatureOffset;
    uint64_t codeSignatureSize;
    uint64_t slideInfoOffsetUnused;
    uint64_t slideInfoSizeUnused;
    uint64_t localSymbolsOffset;
    uint64_t localSymbolsSize;
    uint8_t uuid[16];
    uint64_t cacheType;
    uint32_t branchPoolsOffset;
    uint32_t branchPoolsCount;
    uint64_t accelerateInfoAddr;
    uint64_t accelerateInfoSize;
    uint64_t imagesTextOffset;
    uint64_t imagesTextCount;
    uint64_t patchInfoAddr;
    uint64_t patchInfoSize;
    uint64_t otherImageGroupAddrUnused;
    uint64_t otherImageGroupSizeUnused;
    uint64_t progClosuresAddr;
    uint64_t progClosuresSize;
    uint64_t progClosuresTrieAddr;
    uint64_t progClosuresTrieSize;
    uint32_t platform;
    uint32_t formatVersion:8,
        dylibsExpectedOnDisk:1,
        simulator:1,
        locallyBuiltCache:1,
        builtFromChainedFixups:1,
        padding: 20;
    uint64_t sharedRegionStart;
    uint64_t sharedRegionSize;
    uint64_t maxSlide;
    uint64_t dylibsImageArrayAddr;
    uint64_t dylibsImageArraySize;
    uint64_t dylibsTrieAddr;
    uint64_t dylibsTrieSize;
    uint64_t otherImageArrayAddr;
    uint64_t otherImageArraySize;
    uint64_t otherTrieAddr;
    uint64_t otherTrieSize;
    uint32_t mappingWithSlideOffset;
    uint32_t mappingWithSlideCount;
    uint64_t dylibsPBLStateArrayAddrUnused;
    uint64_t dylibsPBLSetAddr;
    uint64_t programsPBLSetPoolAddr;
    uint64_t programsPBLSetPoolSize;
    uint64_t programTrieAddr;
    uint32_t programTrieSize;
    uint32_t osVersion;
    uint32_t altPlatform;
    uint32_t altOsVersion;
    uint64_t swiftOptsOffset;
    uint64_t swiftOptsSize;
    uint32_t subCacheArrayOffset;
    uint32_t subCacheArrayCount;
    uint8_t symbolFileUUID[16];
    uint64_t rosettaReadOnlyAddr;
    uint64_t rosettaReadOnlySize;
    uint64_t rosettaReadWriteAddr;
    uint64_t rosettaReadWriteSize;
    uint32_t imagesOffset;
    uint32_t imagesCount;
    uint32_t cacheSubType;
    uint64_t objcOptsOffset;
    uint64_t objcOptsSize;
    uint64_t cacheAtlasOffset;
    uint64_t cacheAtlasSize;
    uint64_t dynamicDataOffset;
    uint64_t dynamicDataMaxSize;
} dyld_cache_header_t;

typedef struct {
    uint32_t version;
    uint32_t infoArrayCount;
    const struct dyld_image_info *infoArray;
    dyld_image_notifier notification;
    bool processDetachedFromSharedRegion;
    bool libSystemInitialized;
    const struct mach_header *dyldImageLoadAddress;
    void *jitInfo;
    const char *dyldVersion;
    const char *errorMessage;
    uintptr_t terminationFlags;
    void *coreSymbolicationShmPage;
    uintptr_t systemOrderFlag;
    uintptr_t uuidArrayCount;
    const struct dyld_uuid_info *uuidArray;
    struct dyld_all_image_infos *dyldAllImageInfosAddress;
    uintptr_t initialImageCount;
    uintptr_t errorKind;
    const char *errorClientOfDylibPath;
    const char *errorTargetDylibPath;
    const char *errorSymbol;
    uintptr_t sharedCacheSlide;
    uint8_t sharedCacheUUID[16];
    uintptr_t sharedCacheBaseAddress;
    uint64_t infoArrayChangeTimestamp;
    const char *dyldPath;
    mach_port_t notifyPorts[DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT];
    uintptr_t reserved[11-(DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT/2)];
    uint64_t sharedCacheFSID;
    uint64_t sharedCacheFSObjID;
    uintptr_t compact_dyld_image_info_addr;
    size_t compact_dyld_image_info_size;
    uint32_t platform;
    uint32_t aotInfoCount;
    const struct dyld_aot_image_info* aotInfoArray;
    uint64_t aotInfoArrayChangeTimestamp;
    uintptr_t aotSharedCacheBaseAddress;
    uint8_t aotSharedCacheUUID[16];
} dyld_all_image_infos_t;

typedef struct  {
    uint32_t nlistOffset;
    uint32_t nlistCount;
    uint32_t stringsOffset;
    uint32_t stringsSize;
    uint32_t entriesOffset;
    uint32_t entriesCount;
} dyld_cache_local_symbols_info_t;

typedef struct {
    uint64_t address;
    uint64_t modTime;
    uint64_t inode;
    uint32_t pathFileOffset;
    uint32_t pad;
} dyld_cache_image_info_t;

typedef struct  {
    uint32_t dylibOffset;
    uint32_t nlistStartIndex;
    uint32_t nlistCount;
} dyld_cache_local_symbols_entry_t;

typedef struct  {
    uint64_t dylibOffset;
    uint32_t nlistStartIndex;
    uint32_t nlistCount;
} dyld_cache_local_symbols_entry_64_t;

typedef struct {
    void *aligned_data;
    uint32_t aligned_size;
    void *data;
    uint32_t size;
} dyld_cache_ranged_mapping_t;

typedef struct {
    dyld_cache_header_t *cache_hdr;
    uintptr_t cache_slide;
    uintptr_t dyld_base;
    dyld_cache_ranged_mapping_t *entry_mapping;
    dyld_cache_ranged_mapping_t *symbol_mapping;
    dyld_cache_ranged_mapping_t *string_mapping;
    dyld_cache_local_symbols_info_t symbol_info;
    bool legacy_entries;
} dyld_info_t;

extern const char *dyld_shared_cache_file_path(void);

void *dyld_cache_find_symbol(const char *path, const char *name);
void *dyld_find_symbol(const char *name);
void dyld_deinit(void);
int dyld_init(void);

#endif /* basebin_dyld_h */
