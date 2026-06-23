#ifndef launchd_hook_info_h
#define launchd_hook_info_h

#include "basebin_common.h"
#include <CoreFoundation/CoreFoundation.h>
#include <stdatomic.h>

#define TF_PLATFORM                             0x00000400
#define CS_OPS_STATUS                           0x00000000
#define PROC_PIDPATHINFO                        11
#define PROC_PIDPATHINFO_SIZE                   1024
#define PROC_PIDPATHINFO_MAXSIZE                (4*1024)
#define PROC_ALL_PIDS                           1
#define RB2_USERREBOOT                          0x2000000000000000LLU

#define koffsetof(struct, entry) kinfo->offsets.struct.entry
#define atomic_read32(var) ((uint32_t)atomic_load_explicit(&var, memory_order_seq_cst))
#define atomic_write32(var, value) (atomic_store_explicit(&var, (uint32_t)(value), memory_order_seq_cst))

typedef struct {
    uint64_t self_task_addr;
    uint64_t self_proc_addr;
    uint64_t self_port_addr;
    uint64_t kern_task_addr;
    uint64_t kern_proc_addr;
    uint64_t kernel_base;
    uint64_t kernel_slide;
    uint32_t page_size;
    mach_port_t tfp0;
    uint64_t self_ttep;
    uint64_t cpu_ttep;
    uint32_t version[3];
    
    struct {
        bool kpp;
        bool ktrr;
        bool pan;
        bool pac;
        bool ppl;
    } protections;
    
    struct {
        struct {
            uint32_t bsd_info;
            uint32_t vm_map;
            uint32_t next;
            uint32_t itk_space;
            uint32_t t_flags;
            uint32_t transfer_memory_ownership;
        } task;

        struct {
            uint32_t pid;
            uint32_t p_fd;
            uint32_t p_flag;
            uint32_t p_svuid;
            uint32_t p_svgid;
            uint32_t ucred;
            uint32_t csflags;
            uint32_t p_textvp;
        } proc;
        
        struct {
            uint32_t cr_uid;
            uint32_t cr_ruid;
            uint32_t cr_svuid;
            uint32_t cr_groups;
            uint32_t cr_rgid;
            uint32_t cr_svgid;
            uint32_t cr_label;
        } ucred;
        
        struct {
            uint32_t slots;
        } label;
        
        struct {
            uint32_t fd_ofiles;
        } filedesc;
        
        struct {
            uint32_t f_fglob;
        } fileproc;
        
        struct {
            uint32_t fg_data;
        } fileglob;
        
        struct {
            uint32_t ip_bits;
            uint32_t ikmq_base;
            uint32_t ip_receiver;
            uint32_t ip_kobject;
        } ipc_port;
        
        struct {
            uint32_t is_table_size;
            uint32_t is_table;
        } ipc_space;
        
        struct {
            uint32_t namecache;
            uint32_t ubcinfo;
        } vnode;

        struct {
            uint32_t flags;
        } specinfo;

        struct {
            uint32_t cs_blob;
        } ubc_info;
        
        struct {
            uint32_t vnode;
        } namecache;
        
        struct {
            uint32_t pmap;
            uint32_t flags;
        } vm_map;
        
        struct {
            uint32_t ttep;
            uint32_t cs_enforced;
        } pmap;

        struct {
            uint32_t trust;
        } pmap_cs_code_directory;
    } offsets;
    
    struct {
        uint64_t dynamic_trustcache;
        uint64_t static_trustcache;
        uint64_t ptov_table;
        uint64_t gPhysBase;
        uint64_t gVirtBase;
    } patches;
} kinfo_t;

typedef struct {
    _Atomic uint32_t initialized;
    _Atomic uint32_t userspace_rebooting;
    _Atomic uint32_t shutting_down;
    _Atomic uint32_t first_run;
    _Atomic uint32_t using_tnsv2;
} launchd_info_t;

extern CFDictionaryRef _CFCopySystemVersionDictionary(void);
extern kinfo_t *kinfo;
extern launchd_info_t *launchd_info;

#endif /* launchd_hook_info_h */