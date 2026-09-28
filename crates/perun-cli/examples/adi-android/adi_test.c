/*
 * Copyright 2026 lazyeel (https://github.com/lazyeel)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * adi_test: Phase-1 tester for the ADI engine from Apple Music (Android).
 *
 * Loads libstoreapi.so (successor of libstoreservicescore.so), resolves the
 * classic obfuscated ADI symbols, provisions this "virtual device" against
 * Apple's GrandSlam provisioning endpoints and finally mints one honest
 * anisette token pair (X-Apple-I-MD / X-Apple-I-MD-M).
 *
 * Protocol reference: Dadoum/Provision (lib/provision/adi.d),
 * SideStore/apple-private-apis (omnisette/src/adi_proxy.rs).
 *
 * Build (Termux):
 *   clang adi_test.c -O2 -Wall -o adi_test -ldl -lcurl -lcrypto \
 *        -Wl,-rpath,$ORIGIN/libs
 * Run:
 *   ./adi_test            # state lives in ./adi-data, identifier in ./adi_identifier
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <signal.h>

/* ── ADI function prototypes (ABI per Provision/adi.d) ─────────────────── */
typedef int  (*ADI_LoadLibraryWithPath_t)(const char *dir);
typedef int  (*ADI_SetAndroidID_t)(const char *id, uint32_t len);
typedef int  (*ADI_SetProvisioningPath_t)(const char *path);
typedef int  (*ADI_GetLoginCode_t)(uint64_t ds_id);
typedef int  (*ADI_OTPRequest_t)(uint64_t ds_id, uint8_t **mid, uint32_t *mid_len,
                                 uint8_t **otp, uint32_t *otp_len);
typedef int  (*ADI_ProvisioningStart_t)(uint64_t ds_id, const uint8_t *spim, uint32_t spim_len,
                                        uint8_t **cpim, uint32_t *cpim_len, uint32_t *session);
typedef int  (*ADI_ProvisioningEnd_t)(uint32_t session,
                                      const uint8_t *ptm, uint32_t ptm_len,
                                      const uint8_t *tk,  uint32_t tk_len);
typedef int  (*ADI_Dispose_t)(void *ptr);

/* Classic stable obfuscated export names (Apple Music <=5.x,
 * byte-verified against the shipped libstoreservicescore.so). */
static const char *N_LOAD      = "kq56gsgHG6";
static const char *N_SETID     = "Sph98paBcz";
static const char *N_SETPATH   = "nf92ngaK92";
static const char *N_LOGINCODE = "aslgmuibau";
static const char *N_OTP       = "qi864985u0";
static const char *N_START     = "rsegvyrt87";
static const char *N_END       = "uv5t6nhkui";
static const char *N_DISPOSE   = "jk24uiwqrg";

/* Anonymous-machine constant. SideStore: pub const DS_ID: i64 = -2.
 * (uint64_t)-2 == 0xFFFFFFFFFFFFFFFE: the old 0xFF..FF literal was
 * -1 and silently poisoned every ADI call, surfacing as -29003
 * environment mismatch at finishMachineProvisioning. */
#define DS_ID ((uint64_t)-2)

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[FATAL] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}
static void info(const char *tag, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf("[%s] ", tag);
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

/* ── tiny base64 ───────────────────────────────────────────────────────── */
static const char B64T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char *b64_encode(const uint8_t *in, size_t n) {
    char *out = malloc(((n + 2) / 3) * 4 + 1);
    size_t i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        uint32_t v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
        out[o++] = B64T[(v >> 18) & 63]; out[o++] = B64T[(v >> 12) & 63];
        out[o++] = B64T[(v >> 6) & 63];  out[o++] = B64T[v & 63];
    }
    if (i < n) {
        uint32_t v = in[i] << 16;
        int rem = (int)(n - i);
        if (rem == 2) v |= in[i+1] << 8;
        out[o++] = B64T[(v >> 18) & 63]; out[o++] = B64T[(v >> 12) & 63];
        out[o++] = rem == 2 ? B64T[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = 0;
    return out;
}
static int b64_val(char c) {
    const char *p = strchr(B64T, c);
    if (c == '=') return 0;
    if (!p) return -1;
    return (int)(p - B64T);
}
static uint8_t *b64_decode(const char *in, size_t *out_n) {
    size_t n = strlen(in), o = 0, i;
    uint8_t *out = malloc(n / 4 * 3 + 4);
    uint32_t acc = 0; int bits = 0;
    for (i = 0; i < n; i++) {
        int v = b64_val(in[i]);
        if (v < 0 || in[i] == '=') break;
        acc = (acc << 6) | (uint32_t)v; bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (uint8_t)((acc >> bits) & 0xFF); }
    }
    *out_n = o;
    return out;
}

/* ── xml value extraction (good enough for Apple plists here) ──────────── */
/* finds <key>K</key> ... following <string>VALUE</string>; returns strdup */
static char *xml_string_after_key(const char *xml, const char *key) {
    char pat[256];
    snprintf(pat, sizeof pat, "<key>%s</key>", key);
    const char *k = strstr(xml, pat);
    if (!k) return NULL;
    const char *s = strstr(k, "<string>");
    if (!s) return NULL;
    s += strlen("<string>");
    const char *e = strstr(s, "</string>");
    if (!e) return NULL;
    size_t n = (size_t)(e - s);
    char *out = malloc(n + 1);
    memcpy(out, s, n);
    out[n] = 0;
    /* unescape minimal XML entities */
    return out;
}

/* ── HTTP via libcurl ──────────────────────────────────────────────────── */
typedef struct { char *data; size_t len; } buf;

static const char *g_stage = "startup";
static void on_crash(int sig) {
    fprintf(stderr, "\n[FATAL] signal %d caught at stage: %s\n", sig, g_stage);
    _exit(139);
}

static size_t wr_cb(void *p, size_t sz, size_t nm, void *ud) {
    buf *b = (buf *)ud;
    b->data = realloc(b->data, b->len + sz * nm + 1);
    memcpy(b->data + b->len, p, sz * nm);
    b->len += sz * nm;
    b->data[b->len] = 0;
    return sz * nm;
}

static char g_uuid[64], g_lu[80], g_srl[24];
static char g_adi_ident[8];

/* One keep-alive handle for the whole provisioning cycle: Provision keeps a
 * single Request object across lookup -> start -> finish, i.e. Apple sees
 * the whole dance over ONE connection. Header set matches Provision's
 * ProvisioningSession exactly (note: AuthKit posts XML bodies with a
 * form-urlencoded Content-Type: quirk of akd). */
static CURL *g_http = NULL;
static struct curl_slist *g_hdr_base = NULL;

static void http_ensure(void) {
    if (g_http) return;
    CURL *c = curl_easy_init();
    struct curl_slist *h = NULL;
    const char *ua = getenv("ADI_UA");
    const char *ci = getenv("ADI_CLIENT_INFO");
    char hdr[600];
    snprintf(hdr, sizeof hdr, "User-Agent: %s",
             ua ? ua : "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0");
    h = curl_slist_append(h, hdr);
    h = curl_slist_append(h, "Content-Type: application/x-www-form-urlencoded");
    h = curl_slist_append(h, "Connection: keep-alive");
    snprintf(hdr, sizeof hdr, "X-Mme-Device-Id: %s", g_uuid);
    h = curl_slist_append(h, hdr);
    snprintf(hdr, sizeof hdr, "X-MMe-Client-Info: %s",
             ci ? ci : "<MacBookPro13,2> <macOS;13.1;22C65>"
                       " <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>");
    h = curl_slist_append(h, hdr);
    info("net", "UA=%s", ua ? ua : "(default akd)");
    info("net", "ClientInfo=%s", ci ? ci : "(default MacBookPro)");
    snprintf(hdr, sizeof hdr, "X-Apple-I-MD-LU: %s", g_lu);
    h = curl_slist_append(h, hdr);
    h = curl_slist_append(h, "X-Apple-Client-App-Name: Setup");

    g_hdr_base = h;                 /* base without Client-Time */
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, wr_cb);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 20L);

    /* CA strategy: pin the verified Apple chain (see apple_chain.pem). */
    {
        static const char *pins[] = { "apple_chain.pem", "libs/apple_chain.pem", NULL };
        const char *found = NULL;
        for (int i = 0; pins[i]; i++)
            if (access(pins[i], R_OK) == 0) { found = pins[i]; break; }
        if (!found && getenv("CA_BUNDLE") && access(getenv("CA_BUNDLE"), R_OK) == 0)
            found = getenv("CA_BUNDLE");
        if (!found) {
            static const char *bundles[] = {
                "/data/data/com.termux/files/usr/etc/tls/cert.pem",
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                NULL,
            };
            for (int i = 0; bundles[i]; i++)
                if (access(bundles[i], R_OK) == 0) { found = bundles[i]; break; }
        }
        if (!found)
            fprintf(stderr, "[WARN] no CA bundle/pin file found\n");
        curl_easy_setopt(c, CURLOPT_CAINFO, found);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, found ? 1L : 0L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, found ? 2L : 0L);
    }
    if (getenv("ADI_DEBUG"))
        curl_easy_setopt(c, CURLOPT_VERBOSE, 1L);
    g_http = c;
}

static struct curl_slist *slist_dup(struct curl_slist *src) {
    struct curl_slist *dst = NULL;
    for (; src; src = src->next) dst = curl_slist_append(dst, src->data);
    return dst;
}

static char *perform(const char *url, const char *post_body) {
    http_ensure();
    /* Name resolution bypass.
     *
     * Bionic does not read resolv.conf on this path: android_getaddrinfo goes
     * to netd over the dnsproxyd socket, and there is no netd under qemu-user.
     * CURLOPT_RESOLVE answers the lookup inside curl instead, so the TLS path
     * and the Host header are untouched -- only the address lookup is
     * short-circuited. ADI_RESOLVE carries the list ("host:port:addr" entries,
     * curl's own syntax) so the addresses are not baked into the source.
     */
    {
        const char *rl = getenv("ADI_RESOLVE");
        if (rl && *rl) {
            struct curl_slist *rs = NULL;
            char *dup = strdup(rl), *save = NULL;
            for (char *tok = strtok_r(dup, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
                rs = curl_slist_append(rs, tok);
            /* curl takes ownership of the list */
            curl_easy_setopt(g_http, CURLOPT_RESOLVE, rs);
            free(dup);
        }
    }
    buf b = {malloc(1), 0};
    b.data[0] = 0;
    curl_easy_setopt(g_http, CURLOPT_WRITEDATA, &b);
    if (post_body) {
        curl_easy_setopt(g_http, CURLOPT_HTTPGET, 0L);
        curl_easy_setopt(g_http, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(g_http, CURLOPT_POSTFIELDS, post_body);
        curl_easy_setopt(g_http, CURLOPT_URL, url);
    } else {
        curl_easy_setopt(g_http, CURLOPT_CUSTOMREQUEST, NULL);
        curl_easy_setopt(g_http, CURLOPT_POSTFIELDS, NULL);
        curl_easy_setopt(g_http, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(g_http, CURLOPT_URL, url);
    }
    /* fresh X-Apple-I-Client-Time per request, as AuthKit does:
     * duplicate the base header list and append the current stamp */
    {
        time_t t = time(NULL);
        char cthdr[96];
        const char *tf = getenv("ADI_TIME_FMT");
        if (tf && !strcmp(tf, "utc")) {
            struct tm tm; gmtime_r(&t, &tm);
            strftime(cthdr, sizeof cthdr, "X-Apple-I-Client-Time: %Y-%m-%dT%H:%M:%SZ", &tm);
        } else if (1) {
            /* Provision: Clock.currTime().stripMilliseconds().toISOExtString()
             * = LOCAL time with numeric offset, e.g. 2026-08-22T23:52:43+04:00 */
            struct tm tm; localtime_r(&t, &tm);
            char datebuf[40], zz[8];
            strftime(datebuf, sizeof datebuf, "%Y-%m-%dT%H:%M:%S", &tm);
            strftime(zz, sizeof zz, "%z", &tm);            /* +0400 */
            char off[8]; snprintf(off, sizeof off, "%.3s:%.2s", zz, zz + 3);
            snprintf(cthdr, sizeof cthdr, "X-Apple-I-Client-Time: %s%s", datebuf, off);
        } else {
            struct tm tm; gmtime_r(&t, &tm);
            strftime(cthdr, sizeof cthdr, "X-Apple-I-Client-Time: %Y-%m-%dT%H:%M:%SZ", &tm);
        }
        struct curl_slist *hl = slist_dup(g_hdr_base);
        hl = curl_slist_append(hl, cthdr);
        curl_easy_setopt(g_http, CURLOPT_HTTPHEADER, hl);
    }
    info("net", "%s %s", post_body ? "POST" : "GET ", url);
    CURLcode rc = curl_easy_perform(g_http);
    long code = 0;
    curl_easy_getinfo(g_http, CURLINFO_RESPONSE_CODE, &code);
    if (rc != CURLE_OK) die("%s %s failed: %s", post_body ? "POST" : "GET", url, curl_easy_strerror(rc));
    info("net", "-> %ld (%zu bytes)", code, b.len);
    if (code != 200) {
        fprintf(stderr, "[FATAL] HTTP %ld for %s\nFULL BODY:\n%s\n",
                code, url, b.len ? b.data : "(empty)");
        exit(1);
    }
    if (b.len == 0) die("empty response body from %s", url);
    return b.data;
}

static char *http_get(const char *url) { return perform(url, NULL); }
static char *http_post_plist(const char *url, const char *body) { return perform(url, body); }

/* ── device identity (SideStore-style) ─────────────────────────────────── */
static void load_or_create_identity(void) {
    static const char *fname = "adi_identifier";
    FILE *f = fopen(fname, "rb");
    uint8_t id[16];
    int fresh = 0;
    if (f) {
        if (fread(id, 1, 16, f) != 16) { fclose(f); fresh = 1; }
        else fclose(f);
    } else fresh = 1;
    if (fresh) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0 || read(fd, id, 16) != 16) die("cannot gather randomness");
        close(fd);
        f = fopen(fname, "wb");
        if (!f || fwrite(id, 1, 16, f) != 16) die("cannot persist identifier");
        fclose(f);
        info("id", "generated new device identifier");
    } else info("id", "loaded existing device identifier");

    /* Identity per Provision's WORKING retrieve_headers/app.d:
     *   uniqueDeviceIdentifier = randomUUID().toString().toUpper()  -> 36 dashed, X-Mme-Device-Id
     *   adiIdentifier          = 2 random bytes -> 4 lowercase hex  -> SetAndroidID
     *   localUserUUID          = 8 random bytes -> 16 uppercase hex -> X-Apple-I-MD-LU
     * The cpim envelope binds the adiIdentifier; header identity must match
     * the same device.json triple, or finishMachineProvisioning answers
     * -29003 environment mismatch. */
    {
        static const char *hx = "0123456789abcdef";
        g_adi_ident[0]=hx[id[0]>>4];  g_adi_ident[1]=hx[id[0]&15];
        g_adi_ident[2]=hx[id[1]>>4];  g_adi_ident[3]=hx[id[1]&15];
        g_adi_ident[4]=0;
    }
    snprintf(g_uuid, sizeof g_uuid,
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             id[0],id[1],id[2],id[3],id[4],id[5],id[6],id[7],
             id[8],id[9],id[10],id[11],id[12],id[13],id[14],id[15]);
    {
        /* localUserUUID = first 8 bytes of the SAME random identity,
         * as 16 uppercase hex (Provision: rndGen.take(8).toHexString) */
        for (int i = 0; i < 8; i++) sprintf(g_lu + i*2, "%02X", id[i+2]);
        g_lu[16] = 0;
    }
    /* deterministic plausible serial from the LU hash */
    static const char *alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 12; i++)
        g_srl[i] = alpha[(g_lu[i] + g_lu[i + 12]) % 34];
    g_srl[12] = 0;
    info("id", "UUID=%s", g_uuid);
    info("id", "MD-LU=%s", g_lu);
    info("id", "SRL-NO=%s", g_srl);
}

/* ── plist bodies ──────────────────────────────────────────────────────── */
static const char *PLIST_HEAD =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""
    " \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\"><dict>";

static const char *PLIST_TAIL = "</dict></plist>\n";

/* ── main ──────────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    signal(SIGSEGV, on_crash);
    signal(SIGABRT, on_crash);
    signal(SIGBUS,  on_crash);
    const char *libdir = argc > 1 ? argv[1] : NULL;
    char libdir_buf[128];
    if (!libdir) {
        /* pick whichever kit actually lives next to us */
        /* classic kit wins when both are present */
        static const char *kits[][2] = {
            { "./libs-classic", "libstoreservicescore.so" },
            { "./libs",         "libstoreservicescore.so" },
            { "./libs",         "libstoreapi.so" },
        };
        for (int i = 0; i < 3 && !libdir; i++) {
            snprintf(libdir_buf, sizeof libdir_buf, "%s/%s",
                     kits[i][0], kits[i][1]);
            if (access(libdir_buf, R_OK) == 0) libdir = kits[i][0];
        }
        if (!libdir) die("no library kit found (need ./libs or ./libs-classic)");
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    load_or_create_identity();
    mkdir("adi-data", 0755);

    /* 1. load the CLASSIC stack (Apple Music <=5.x): libstoreservicescore.so
     * carries the original stable obfuscated exports that Provision maps.
     * Preload order matters: ICU -> xml2 -> blocks -> dispatch -> c++ ->
     * CoreFoundation -> mediaplatform -> CoreADI, then the entry point.
     * All RTLD_LOCAL: Apple's bundled zlib/allocators must NOT interpose on
     * libcurl's bindings in the global namespace. */
    char so[1024];
    static const char *deps[] = {
        "libc++_shared.so",                    /* first: ICU links against it */
        "libicudata_sv_apple.so", "libicuuc_sv_apple.so", "libicui18n_sv_apple.so",
        "libxml2.so", "libBlocksRuntime.so", "libdispatch.so",
        "libCoreFoundation.so", "libmediaplatform.so",
        "libCoreADI.so",
    };
    for (size_t i = 0; i < sizeof deps / sizeof deps[0]; i++) {
        snprintf(so, sizeof so, "%s/%s", libdir, deps[i]);
        if (access(so, R_OK) != 0) continue; /* optional dep */
        void *hd = dlopen(so, RTLD_NOW | RTLD_LOCAL);
        if (!hd) die("dlopen %s: %s", so, dlerror());
        info("dl", "preloaded %s", deps[i]);
    }

    snprintf(so, sizeof so, "%s/libstoreservicescore.so", libdir);
    info("dl", "dlopen %s", so);
    void *h = dlopen(so, RTLD_NOW | RTLD_LOCAL);
    if (!h) die("dlopen libstoreservicescore.so: %s", dlerror());

#ifdef DUMP_ADI
    /* Install the argument dumper after both libraries are mapped and before
     * any entry point is called. The hooks are inline patches, so they take
     * effect regardless of which pointer the caller holds. */
    extern int dump_init(const char *);
    if (dump_init(libdir) == 0)
        die("dump_init(%s) failed", libdir);
#endif

    /* Classic stable obfuscated exports (byte-verified in this exact .so):
     * kq56gsgHG6=LoadLibraryWithPath Sph98paBcz=SetAndroidID
     * nf92ngaK92=SetProvisioningPath aslgmuibau=GetLoginCode
     * qi864985u0=OTPRequest rsegvyrt87=ProvisioningStart
     * uv5t6nhkui=ProvisioningEnd jk24uiwqrg=Dispose */
#define RESOLVE(var, type, name)                                  \
    type var = (type)dlsym(h, name);                              \
    if (!var) die("dlsym(%s) failed: %s", name, dlerror());
    RESOLVE(pLoad,   ADI_LoadLibraryWithPath_t,   N_LOAD);
    RESOLVE(pSetID,  ADI_SetAndroidID_t,          N_SETID);
    RESOLVE(pSetPth, ADI_SetProvisioningPath_t,   N_SETPATH);
    RESOLVE(pCode,   ADI_GetLoginCode_t,          N_LOGINCODE);
    RESOLVE(pOTP,    ADI_OTPRequest_t,            N_OTP);
    RESOLVE(pStart,  ADI_ProvisioningStart_t,     N_START);
    RESOLVE(pEnd,    ADI_ProvisioningEnd_t,       N_END);
    RESOLVE(pDisp,   ADI_Dispose_t,               N_DISPOSE);
#undef RESOLVE
    info("dl", "classic obfuscated ADI symbols resolved");

    /* 2. init ADI */
    char absdir[512];
    if (!realpath(libdir, absdir)) die("realpath(%s)", libdir);
    int rc = pLoad(absdir);
    if (rc != 0) die("ADILoadLibraryWithPath(%s)=%d", absdir, rc);
    info("adi", "library loaded (%s)", absdir);

    /* probe: is the engine responsive at all before any configuration? */
    int code = pCode(DS_ID);
    info("adi", "pre-config ADIGetLoginCode=%d%s", code,
         code == 0 ? " (provisioned)" :
         code == -45061 ? " (not provisioned)" : "");

    /* provisioning storage path must exist; make it absolute */
    char absdata[512];
    if (!realpath("adi-data", absdata)) {
        if (mkdir("adi-data", 0755) != 0 || !realpath("adi-data", absdata))
            die("cannot create adi-data");
    }
    if ((rc = pSetPth(absdata)) != 0) die("ADISetProvisioningPath(%s)=%d", absdata, rc);
    info("adi", "provisioning path set (%s)", absdata);

    /* SetAndroidID receives the 4-hex adiIdentifier (Provision canon).
     * Ladder for engine-version differences: 4hex -> 16hex -> 36dashed,
     * keeping X-Mme-Device-Id in sync with whichever is accepted. */
    const char *cands[] = { g_adi_ident, NULL, NULL };
    char h16[17];
    for (int i = 0, j = 0; g_uuid[j]; j++)
        if (g_uuid[j] != '-') h16[i++] = g_uuid[j];
    h16[16] = 0;
    cands[1] = h16;
    cands[2] = g_uuid;
    int accepted_len = -1;
    const char *adi_id = NULL;
    for (int i = 0; i < 3; i++) {
        rc = pSetID(cands[i], (uint32_t)strlen(cands[i]));
        info("adi", "ADISetAndroidID(\"%s\")=%d", cands[i], rc);
        if (rc == 0) { accepted_len = i; adi_id = cands[i]; break; }
    }
    if (accepted_len < 0) die("no identifier format accepted");
    /* Provision canon: X-Mme-Device-Id ALWAYS carries the dashed UUID
     * (uniqueDeviceIdentifier); what the engine accepted stays internal. */
    info("adi", "machine identity: SetAndroidID=\"%s\" X-Mme-Device-Id=%s",
         adi_id, g_uuid);

    code = pCode(DS_ID);
    info("adi", "ADIGetLoginCode=%d%s", code,
         code == 0 ? " (provisioned)" :
         code == -45061 ? " (not provisioned: provisioning now)" : "");

    if (code != 0 && code != -45061) die("ADI login code %d: unexpected", code);

    if (code == -45061) {
        /* 4a. full provisioning cycle */
        char *lookup = http_get("https://gsa.apple.com/grandslam/GsService2/lookup");
        if (getenv("ADI_DUMP_LOOKUP")) { FILE *f = fopen(getenv("ADI_DUMP_LOOKUP"), "wb"); fwrite(lookup, 1, strlen(lookup), f); fclose(f); }
        char *u_start = xml_string_after_key(lookup, "midStartProvisioning");
        char *u_fin   = xml_string_after_key(lookup, "midFinishProvisioning");
        free(lookup);
        if (!u_start || !u_fin) die("url bag did not contain provisioning endpoints");
        info("prov", "start=%s", u_start);
        info("prov", "finish=%s", u_fin);

        char body[4096];
        snprintf(body, sizeof body, "%s<key>Header</key><dict/><key>Request</key><dict/>%s",
                 PLIST_HEAD, PLIST_TAIL);
        char *r1 = http_post_plist(u_start, body);
        if (getenv("ADI_DUMP_START")) { FILE *f = fopen(getenv("ADI_DUMP_START"), "wb"); fwrite(r1, 1, strlen(r1), f); fclose(f); }
        char *spim_b64 = xml_string_after_key(r1, "spim");
        free(r1);
        if (!spim_b64) die("no spim in startProvisioning response");
        size_t spim_n = 0;
        uint8_t *spim = b64_decode(spim_b64, &spim_n);
        info("prov", "spim received (%zu bytes decoded)", spim_n);

        uint8_t *cpim = NULL; uint32_t cpim_n = 0; uint32_t session = 0;
        rc = pStart(DS_ID, spim, (uint32_t)spim_n, &cpim, &cpim_n, &session);
        if (rc != 0) die("ADIProvisioningStart=%d", rc);
        info("prov", "cpim ready (%u bytes, session=%u)", cpim_n, session);

        char *cpim_b64 = b64_encode(cpim, cpim_n);
        snprintf(body, sizeof body,
                 "%s<key>Header</key><dict/>"
                 "<key>Request</key><dict><key>cpim</key><string>%s</string></dict>%s",
                 PLIST_HEAD, cpim_b64, PLIST_TAIL);
        char *r2 = http_post_plist(u_fin, body);
        char *ptm_b64 = xml_string_after_key(r2, "ptm");
        char *tk_b64  = xml_string_after_key(r2, "tk");
        char *rinfo   = xml_string_after_key(r2, "X-Apple-I-MD-RINFO");
        free(r2);
        if (!ptm_b64 || !tk_b64) die("no ptm/tk in finishProvisioning response:\n%.600s", r2 ? "" : "");
        info("prov", "ptm/tk received (routing info: %s)", rinfo ? rinfo : "(none)");

        size_t ptm_n = 0, tk_n = 0;
        uint8_t *ptm = b64_decode(ptm_b64, &ptm_n);
        uint8_t *tk  = b64_decode(tk_b64,  &tk_n);
        rc = pEnd(session, ptm, (uint32_t)ptm_n, tk, (uint32_t)tk_n);
        if (rc != 0) die("ADIProvisioningEnd=%d", rc);
        info("prov", "PROVISIONING COMPLETE");

        code = pCode(DS_ID);
        info("adi", "re-check ADIGetLoginCode=%d", code);
        if (code != 0) die("still not provisioned after successful end()");
    }

    /* 4b. mint one OTP */
    uint8_t *mid = NULL, *otp = NULL;
    uint32_t mid_n = 0, otp_n = 0;
    rc = pOTP(DS_ID, &mid, &mid_n, &otp, &otp_n);
    if (rc != 0) die("ADIOTPRequest=%d", rc);

    char *mid_b64 = b64_encode(mid, mid_n);
    char *otp_b64 = b64_encode(otp, otp_n);
    printf("\n=== SUCCESS ===\n");
    printf("X-Apple-I-MD:   %s\n", otp_b64);
    printf("X-Apple-I-MD-M: %s\n", mid_b64);
    printf("===============\n");

    pDisp(mid); pDisp(otp);
    info("done", "engine works: anisette tokens generated locally");
    return 0;
}
