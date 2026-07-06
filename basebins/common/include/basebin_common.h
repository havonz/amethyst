#ifndef basebins_common_h
#define basebins_common_h

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <time.h>
#include <spawn.h>
#include <pthread.h>
#include <libgen.h>
#include <limits.h>
#include <_ctype.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <sys/dirent.h>
#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <mach/mach_time.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
#include <mach-o/swap.h>
#include <xpc/xpc.h>
#include <objc/objc.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <sys/utsname.h>
#include <sys/attr.h>
#include <sys/fsgetpath.h>
#include <pwd.h>
#include <CommonCrypto/CommonDigest.h>

struct _os_alloc_once_s {
    long once;
    void *ptr;
};

struct xpc_global_data {
    uint64_t a;
    uint64_t xpc_flags;
    mach_port_t task_bootstrap_port;
#ifndef __LP64__
    uint32_t padding;
#endif
    xpc_object_t xpc_bootstrap_pipe;
};

typedef void *xpc_pipe_t;
typedef struct section_64 section_t;
typedef struct segment_command_64 segment_command_t;
typedef struct mach_header_64 mach_header_t;
typedef struct nlist_64 nlist_t;

extern int posix_spawnattr_getprocesstype_np(posix_spawnattr_t *, int *);
extern int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern int proc_name(int pid, void *buffer, uint32_t buffersize);
extern int csops(pid_t pid, unsigned int  ops, void *useraddr, size_t usersize);
extern int ptrace(int request, pid_t pid, uint64_t addr, int data);
extern char ***_NSGetArgv(void);
extern char ***_NSGetEnviron(void);
extern char **_NSGetProgname(void);
mach_header_t *_NSGetMachExecuteHeader(void);
extern char **environ;

extern struct _os_alloc_once_s _os_alloc_once_table[];
extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message, xpc_object_t *reply);
extern int xpc_pipe_receive(mach_port_t port, xpc_object_t *message);
extern void* _os_alloc_once(struct _os_alloc_once_s *slot, size_t sz, os_function_t init);
extern xpc_pipe_t xpc_pipe_create_from_port(mach_port_t port, uint32_t flags);
extern void xpc_dictionary_get_audit_token(xpc_object_t xdict, audit_token_t *token);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern xpc_object_t xpc_create_from_plist(void *data, size_t size);
extern int xpc_pipe_routine_with_flags(xpc_object_t xpc_pipe, xpc_object_t inDict, XPC_GIVES_REFERENCE xpc_object_t *reply, uint32_t flags);
extern char *xpc_strerror(int err);
extern mach_port_t xpc_dictionary_copy_mach_send(xpc_object_t xdict, const char *key);
extern void xpc_dictionary_set_mach_send(xpc_object_t xdict, const char *key, mach_port_t p);

extern int sandbox_check(pid_t pid, const char *operation, uint32_t type, ...);
extern int64_t sandbox_extension_consume(const char *extension_token);
extern int sandbox_check_by_audit_token(audit_token_t at, const char *op, int filter, ...);

#endif /* basebins_common_h */
