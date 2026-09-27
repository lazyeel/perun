/* Placeholder for <openssl/evp.h>.
 *
 * adi_test.c includes this header but calls no OpenSSL function: its base64
 * helper is hand-rolled, and a cross-check of the engine's undefined symbols
 * against aarch64 glibc found every MD5 and SHA import satisfiable inside the
 * APK's libcurl.so, which links BoringSSL statically. Nothing from EVP is
 * reachable from the harness.
 *
 * Vendoring the full OpenSSL header tree to satisfy one unused include would
 * put ~140 files in the repository for no benefit. If a future change does
 * need EVP, install libssl-dev and drop this directory from the include path.
 */
#ifndef ADI_STUB_OPENSSL_EVP_H
#define ADI_STUB_OPENSSL_EVP_H
#endif
