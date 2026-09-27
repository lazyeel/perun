// Minimal liblog.so stand-in for the Android CoreADI build.
//
// libCoreADI.so imports exactly 24 symbols; 23 of them exist in aarch64 glibc
// (including arc4random, added in glibc 2.36). The one that does not is
// __system_property_get, which is an Android property lookup with no glibc
// equivalent -- so this file provides it and nothing else.
//
// The property is what the ADI provisioning path reads to fingerprint the
// device. Returning a fixed, obviously-fake value is deliberate: the point of
// this harness is to learn whether the gate opens, not to impersonate a phone.
#include <stddef.h>
#include <string.h>

int __system_property_get(const char *name, char *value) {
    (void)name;
    if (value) {
        strcpy(value, "perun-standin");
    }
    return 12;
}

// Android's liblog also exports these; CoreADI may reach them through the
// PLT even if they are not in .dynsym, so provide inert versions.
int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    (void)prio; (void)tag; (void)fmt;
    return 0;
}

int __android_log_vprint(int prio, const char *tag, const char *fmt, void *ap) {
    (void)prio; (void)tag; (void)fmt; (void)ap;
    return 0;
}

int __android_log_write(int prio, const char *tag, const char *text) {
    (void)prio; (void)tag; (void)text;
    return 0;
}
