#ifndef jbutil_util_h
#define jbutil_util_h

#include "common.h"

int run_command(const char *path, char **args);
int register_app(const char *path);
int unregister_app(const char *path);
int refresh_icon_cache(void);

#endif /* jbutil_util_h */
