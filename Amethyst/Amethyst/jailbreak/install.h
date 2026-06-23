#ifndef install_h
#define install_h

#include <stdio.h>

static const char *restore_rootfs_leftovers[] = {
    "/var/lib",
    "/var/jb",
    "/var/stash",
    "/var/db/stash",
    "/var/cache",
    "/var/log/apt",
    "/var/log/dpkg",
    "/var/run/sudo",
    "/var/run/utmp",
    "/var/db/sudo",
    "/var/mobile/Library/Filza",
    "/var/mobile/Library/Cydia",
    "/var/log/jailbreakd-stdout.log",
    "/var/log/jailbreakd-stderr.log",
    "/var/log/pspawn_payload_xpcproxy.log",
    "/var/log/suckmyd-stderr.log",
    "/var/log/suckmyd-stdout.log",
    "/var/log/pf-offsets.txt",
    "/var/log/jbme-offsets.txt",
    "/var/log/pspawn_payload.log",
    "/var/log/dpkg",
    "/var/log/apt",
    "/var/run/pspawn_hook.ts",
    "/var/containers/Bundle/stage3",
    "/var/checkra1n.dmg",
    "/var/mobile/.tweaks_disabled",
    "/var/mobile/.safemode",
    "/var/mobile/.safe_mode",
    "/var/LIB",
    "/var/ulb",
    "/var/bin",
    "/var/sbin",
    "/var/libexec",
    "/var/profile",
    "/var/motd",
    "/var/dropbear",
    "/var/etc",
    "/var/usr",
    "/var/Apps",
    "/var/mobile/.zshrc",
    "/var/root/.zshrc",
    "/var/root/.lldb",
    "/var/mobile/Library/Application Support/xyz.willy.Zebra",
    "/var/mobile/Library/Caches/xyz.willy.Zebra",
    "/var/mobile/Library/Caches/Sileo",
    "/var/mobile/Library/Preferences/xyz.willy.Zebra.plist",
    "/var/mobile/Documents/xyz.willy.Zebra",
    "/var/mobile/Library/Caches/org.coolstar.SileoStore",
    "/var/mobile/Library/Preferences/org.coolstar.SileoStore.plist",
    "/var/mobile/Library/Cydia",
    "/var/mobile/Library/Filza",
    "/var/mobile/Library/Caches/Snapshots/com.saurik.Cydia",
    "/var/mobile/Library/Caches/Snapshots/com.tigisoftware.Filza",
    "/var/mobile/Library/Caches/Snapshots/xyz.willy.Zebra",
    "/var/mobile/Library/Caches/Snapshots/org.coolstar.SileoStore",
    "/var/mobile/Library/Caches/com.hackemist.SDImageCache",
    "/var/mobile/Library/Caches/io.sentry",
    "/var/mobile/Library/Caches/SentryCache",
    "/var/mobile/Library/Caches/com.saurik.Cydia",
    "/var/mobile/Library/Caches/com.tigisoftware.Filza",
    "/var/root/Library/Caches/shshd",
    "/var/root/Library/Preferences/com.p4e.freya.plist",
    "/var/containers/Bundle/.installed_rootlessJB4",
    "/var/containers/Bundle/.installed_rootlessJB3",
    "/var/containers/Bundle/tweaksupport",
    "/var/containers/Bundle/iosbinpack64",
    "/var/containers/Bundle/jb",
    NULL
};

/* chimera, odyssey, and odyessyra1n */
static const char *other_jailbreak_leftovers[] = {
    "/var/log/jailbreakd-stdout.log",
    "/var/log/jailbreakd-stderr.log",
    "/var/log/pspawn_payload_xpcproxy.log",
    "/usr/share/jailbreak"
    "/binpack",
    "/var/checkra1n.dmg",
    "/odyssey",
    "/.installed_odyssey",
    "/.installed_chimera",
    "/.bootstrapped_electra",
    "/Library/LaunchDaemons/jailbreakd.plist",
    "/usr/libexec/jailbreakd",
    "/usr/bin/inject_criticald",
    "/usr/lib/pspawn_payload.dylib",
    "/usr/lib/pspawn_payload-stg2.dylib",
    NULL
};

int install_deb(char *path);
int install_tnsv2_support(void);
int install_bootstrap(void);
void migrate_install(void);
void restore_cleanup(void);
bool is_bootstrap_installed(void);
bool is_amethyst_installed(void);
bool is_procursus_installed(void);
int register_app(const char *path);
void verify_install(void);

#endif /* install_h */
