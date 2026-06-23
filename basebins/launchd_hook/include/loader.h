#ifndef launchd_hook_loader_h
#define launchd_hook_loader_h

#include "info.h"
#include "codesign.h"

static const char *path_block_list[] = {
    "/usr/libexec/keybagd",
    "/usr/libexec/FinishRestoreFromBackup",
    "/usr/libexec/sysstatuscheck",
    "/usr/libexec/usermanagerd",
    "/usr/libexec/init_featureflags",
    "/usr/libexec/FinishRestoreFromBackup",
    "/usr/libexec/adprivacyd",
    NULL
};

static const char *xpc_block_list[] = {
    "com.apple.syslogd",
    "com.apple.logd",
    "com.apple.aslmanager",
    "com.apple.MobileInternetSharing", 
    "com.apple.mobile.keybagd",
    "com.apple.notifyd",
    "com.apple.ReportMemoryException",
    "com.apple.GSSCred",
    "com.apple.UIKit.ShareUI",
    "com.apple.MTLCompilerService",
    /*
    "com.apple.syslogd",
    "com.apple.logd",
    "com.apple.aslmanager",
    "com.apple.ReportCrash",
    "com.apple.diagnosticd", 
    "com.apple.mobile.keybagd",
    "com.apple.splashboard",
    "com.apple.UserEventAgent-System",
    "com.apple.mDNSResponder.reloaded",
    "com.apple.notifyd",
    "com.apple.distnoted.xpc.daemon",
    "com.apple.ReportMemoryException",
    "com.apple.GSSCred",
    "com.apple.quicklook.ThumbnailsAgent",
    "com.apple.UIKit.ShareUI",
    "com.apple.MTLCompilerService",
    "com.apple.streaming_zip_conduit",
    "com.apple.StreamingUnzipService",
    "com.apple.mDNSResponder",
    "com.apple.nsurlsessiond",
    "com.apple.mobile.installation_proxy",
    "com.apple.MobileInstallationHelperService",
    "com.apple.itunescloudd",
    "com.apple.swcd",
    "com.apple.usb.networking.addNetworkInterface",
    "com.apple.online-auth-agent.xpc",
    "com.apple.mobile.installation_proxy",
    "lockdown",
    "com.apple.watchdog",
    "com.apple.bluetoothd",
    "com.apple.CryptoTokenKit.setoken",
    "com.apple.mediaserverd",
    "com.apple.mobileassetd",
    "com.apple.CacheDeleteDaily",
    "com.apple.mobileslideshow.photo-picker",
    "com.apple.wifid",
    "com.apple.wifi.wapic",
    "com.apple.wifip2pd",
    "com.apple.wifiFirmwareLoader",
    "com.apple.wifianalyticsd",
    "com.apple.wifi.hostapdc",
    "com.apple.wifivelocityd",
    "com.apple.WirelessRadioManager",
    "com.apple.usb.networking.addNetworkInterface",
    "com.apple.atc",
    "com.apple.cfnetwork.cfnetworkagent",
    "com.apple.networkserviceproxy",
    "com.apple.cfnetwork.AuthBrokerAgent",
    "com.apple.usb.networking.addNetworkInterface",
    "com.apple.pcapd",
    "com.apple.nsurlsessiond",
    "com.apple.mDNSResponderHelper.reloaded",
    "com.apple.mDNSResponder.reloaded",
    "com.apple.mDNSResponderHelper",
    "com.apple.mDNSResponder",
    "com.apple.misagent",
    "com.apple.MobileInternetSharing",
    "com.apple.bluetoothd",
    "com.apple.BlueTool",
    "com.apple.BTServer.cloudpairing",
    "com.apple.BTServer.le",
    "com.apple.BTServer.pbap",
    "com.apple.BTServer.map",
    "com.apple.BTServer.avrcp",
    "com.apple.ap.adprivacyd",
    "com.apple.identityservicesd",
    */
    NULL
};

static const char *jetsam_list[] = {
    "CommCenter",
    "backboardd",
    "SpringBoard",
    "locationd",
    "mediaserverd",
    "com.apple.siri.embeddedspeech",
    NULL
};

typedef int (*orig_spawn_t)(pid_t *, const char *, posix_spawn_file_actions_t *, posix_spawnattr_t *, char **, char **);

int process_binary(const char *path);
int init_loader(void);

#endif /* launchd_hook_loader_h */
